use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{BufWriter, Write};

extern crate clap;
use clap::Parser;

mod ksym;
use ksym::*;

/// eKCFI trace data parsing tool
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Mode of operation, either "pretty-print" or "generate-inc"
    #[arg(short, long)]
    mode: String,

    /// Path to System.map
    system_map: Option<String>,

    /// Path to trace data
    trace_data: Option<String>,

    /// Task to filter
    task: Option<String>,
}

fn pretty_print(ksyms: &Vec<Ksym>, trace_data: &str) {
    // HashMap to store result
    let mut trace_result = HashMap::new();

    // Parse tracing data
    for line in fs::read_to_string(trace_data).unwrap().lines() {
        // Line format:
        // comm-pid     [cpu] flags    time: kcfi_trace: caller => callee
        let split_line: Vec<&str> = line.split_whitespace().collect();

        // Ignore interrupts
        let flags = split_line[2];
        if flags.contains("h") || flags.contains("s") {
            continue;
        }

        // Create an entry for this task if there is not one yet
        let task = split_line[0];
        let calls = trace_result
            .entry(task.to_string())
            .or_insert(Vec::<String>::new());

        // Parse caller and callee address
        let caller_addr = u64::from_str_radix(split_line[5].trim_start_matches("0x"), 16).unwrap();
        let callee_addr = u64::from_str_radix(split_line[7].trim_start_matches("0x"), 16).unwrap();

        // Do a binary search using a dummy Ksym obj
        let caller_result = &ksyms[..].binary_search(&Ksym::new(caller_addr, KsymType::Text, ""));
        let caller = match caller_result {
            // offset = 0, we get exact index (unlikely)
            Ok(idx) => &ksyms[*idx],
            // offset != 0, we get index + 1, i.e. where this address could
            // be inserted to maintain sorting order (common case)
            Err(idx) => &ksyms[idx - 1],
        };

        // Callee addr is always exact -- one cannot call into the middle of
        // a function
        let callee_idx = *&ksyms[..]
            .binary_search(&Ksym::new(callee_addr, KsymType::Text, ""))
            .expect("Invalid callee function pointer");
        let callee = &ksyms[callee_idx];

        if caller.is_pf_handler() {
            // do_fault
            calls.push("<page fault>".to_string());
        } else if caller.is_syscall_entry() {
            // do_syscall_64
            calls.push(format!(
                "<syscall> {}",
                callee.get_name().trim_start_matches("__x64_sys_")
            ));
        } else {
            // Normal indirect calls
            calls.push(format!(
                "{}+{:#x} => {}",
                caller.get_name(),
                caller_addr - caller.get_base_addr(),
                callee.get_name()
            ));
        }
    }

    // Dump result
    for (task, calls) in &trace_result {
        for call in calls {
            println!("{}\t{}", task, call);
        }
        println!();
    }
}

fn generate_inc(trace_data: &str, target_task: &str) {
    let mut trace_result = HashMap::new();
    let xdim: usize;
    let mut ydim: usize = 0;

    // Parse tracing data
    for line in fs::read_to_string(trace_data).unwrap().lines() {
        // Line format:
        // comm-pid     [cpu] flags    time: kcfi_trace: caller => callee
        let split_line: Vec<&str> = line.split_whitespace().collect();
        let task = split_line[0];

        if !task.starts_with(target_task) {
            continue;
        }

        // Parse caller and callee address
        let caller_addr = u64::from_str_radix(split_line[5].trim_start_matches("0x"), 16).unwrap();
        let callee_addr = u64::from_str_radix(split_line[7].trim_start_matches("0x"), 16).unwrap();

        let entry = trace_result.entry(caller_addr).or_insert(HashSet::<u64>::new());
        entry.insert(callee_addr);
        if entry.len() > ydim {
            ydim = entry.len();
        }
    }
    xdim = trace_result.len();

    let f = fs::File::create("traces.inc").unwrap();
    {
        let mut writer = BufWriter::new(f);

        // eBPF side map definition
        writer.write(b"#ifdef __EBPF__\n\n").unwrap();

        writer.write_fmt(format_args!("#define NR_CALLEES {}\n\
            struct {{\n\
            \t__uint(type, BPF_MAP_TYPE_HASH);\n\
            \t__type(key, __u32);\n\
            \t__type(value, __u64 [NR_CALLEES]);\n\
            \t__uint(max_entries, 1024);\n\
            }} call_map SEC(\".maps\");\n", ydim)).unwrap();

        // Userside structure
        writer.write(b"\n#else /* !__EBPF__ */\n\n").unwrap();

        writer.write_fmt(format_args!(
            "static struct {{\n\tunsigned long long caller;\n\
            \tunsigned long long callees[{}];\n}} call_trace [{}] = {{\n", ydim, xdim)).unwrap();

        for (caller, callees) in trace_result.iter() {
            writer.write(b"\t{\n").unwrap();
            writer.write_fmt(format_args!("\t\t.caller = {:#x}ULL,\n", caller)).unwrap();
            writer.write(b"\t\t.callees = {\n").unwrap();
            for (idx, callee) in callees.iter().enumerate() {
                writer.write_fmt(format_args!("\t\t\t[{}] = {:#x}ULL,\n", idx, callee)).unwrap();
            }
            writer.write(b"\t\t},\n").unwrap();
            writer.write(b"\t},\n").unwrap();
        }

        writer.write(b"};\n").unwrap();

        writer.write(b"\n#endif /* __EBPF__ */\n").unwrap();
    }
}

fn main() {
    let args = Args::parse();
    let trace_data = args.trace_data.expect("expecting trace data file");

    match &args.mode[..] {
        "pretty-print" => {
            // Read System.map (kernel symbols), sorted by addresses
            let ksyms = parse_system_map(&args.system_map.expect("expecting System.map")).unwrap();
            pretty_print(&ksyms, &trace_data);
        }
        "generate-inc" => {
            let target_task = args.task.expect("expecting task name");
            generate_inc(&trace_data, &target_task);
        }
        _ => panic!("invalid mode of operation"),
    }
}
