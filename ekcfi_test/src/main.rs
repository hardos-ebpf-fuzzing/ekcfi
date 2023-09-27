use std::io::Write;
use std::{collections::HashMap, process::Command};
use std::fs;
use std::iter::zip;
use std::mem;
use std::os::fd::AsRawFd;
use std::path::PathBuf;

extern crate elf;
use elf::endian::AnyEndian;
use elf::ElfBytes;

extern crate libc;
use libc::{__errno_location, ioctl, perror, syscall};

extern crate clap;
use clap::Parser;

mod ksym;
use crate::ksym::*;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct __EkcfiAttrS1 {
    addrs: *const u64,
    len: u64,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct __EkcfiAttrS2 {
    poke_queue_addr: u64,
    poke_finish_addr: u64,
    text_mutex_addr: u64,
}

#[repr(C)]
union ekcfi_attr {
    target_addr: u64,
    __s1: __EkcfiAttrS1,
    __s2: __EkcfiAttrS2,
    prog_fd: u32,
}

#[allow(non_camel_case_types)]
#[allow(unused)]
enum EKCFI_CMD {
    EKCFI_LOAD_TBL = 1313,
    EKCFI_ENABLE_ENTRY = 1314,
    EKCFI_ENABLE_ALL = 1315,
    EKCFI_DEFINE_SYM = 1316,
    EKCFI_ATTACH_BPF = 1317,
}

#[allow(non_upper_case_globals)]
const SYS_kcfi_bench: i64 = 451;

// data16 data16 cs nopw 0x200(%rax,%rax,1)
const NOP5: [u8; 5] = [0x0f, 0x1f, 0x44, 0x00, 0x08];

#[inline(always)]
fn is_nop5(vals: &[u8]) -> bool {
    if vals.len() != NOP5.len() {
        return false;
    }

    for (it1, it2) in zip(vals.iter(), NOP5.iter()) {
        if *it1 != *it2 {
            return false;
        }
    }

    true
}

unsafe fn ekcfi_ctl(cmd: EKCFI_CMD, attr: &ekcfi_attr) -> Result<i64, i64> {
    let errno: &mut i32 = unsafe { &mut *__errno_location() };
    *errno = 0;

    let file = fs::File::options()
        .read(true)
        .write(true)
        .open("/proc/ekcfi")
        .expect("/proc/ekcfi does not exist");

    let ret = unsafe {
        ioctl(
            file.as_raw_fd(),
            cmd as u64,
            attr as *const ekcfi_attr as i64,
        )
    };
    if ret == 0 {
        Ok(0)
    } else {
        Err(*errno as i64)
    }
}

unsafe fn kcfi_bench() -> Result<i64, i64> {
    let errno: &mut i32 = unsafe { &mut *__errno_location() };
    *errno = 0;

    let ret = unsafe { syscall(SYS_kcfi_bench) };
    if ret >= 0 {
        Ok(ret)
    } else {
        Err(*errno as i64)
    }
}

fn syscall_perror(err: i64, s: *const std::ffi::c_char) -> Result<i64, i64> {
    unsafe { perror(s) };
    Err(err)
}

/// eKCFI test program
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Mode of operation, either "trace" or "test"
    #[arg(short, long)]
    mode: String,

    /// Path to vmlinux
    vmlinux: Option<String>,
}

fn trace() {
    let mut attr: ekcfi_attr = unsafe { mem::zeroed() };
    unsafe {
        ekcfi_ctl(EKCFI_CMD::EKCFI_ENABLE_ALL, &mut attr)
            .or_else(|e| syscall_perror(e, "ekcfi_ctl\0".as_ptr() as *const i8))
            .unwrap();
    }

    println!("all entries enabled");
}

fn test() {

    let mut result: u64 = 0;
    for _ in 0..(1 << 12) {
        unsafe {
            let tmp = kcfi_bench()
            .or_else(|e| syscall_perror(e, "kcfi_bench\0".as_ptr() as *const i8))
            .unwrap() as u64;
            result += tmp;
        }
    }
    println!("average cycles: {}", result >> 12);

    let mut attr: ekcfi_attr = unsafe { mem::zeroed() };


    unsafe {
        // FIXME: This may change with each kernel build
        attr.target_addr = 0xffffffff8106ed04;
        ekcfi_ctl(EKCFI_CMD::EKCFI_ENABLE_ENTRY, &mut attr)
            .or_else(|e| syscall_perror(e, "ekcfi_ctl\0".as_ptr() as *const i8))
            .unwrap();
    }

    println!("entry 0xffffffff8106ed04 enabled");

    for _ in 0..100 {
        unsafe {
            kcfi_bench()
                .or_else(|e| syscall_perror(e, "kcfi_bench\0".as_ptr() as *const i8))
                .unwrap();
        }
    }

    let mut result: u64 = 0;
    let mut result_vec = Vec::new();
    for _ in 0..(1 << 12) {
        unsafe {
            let tmp = kcfi_bench()
            .or_else(|e| syscall_perror(e, "kcfi_bench\0".as_ptr() as *const i8))
            .unwrap() as u64;
        result_vec.push(tmp);
            result += tmp;
        }
    }
    println!("average cycles: {}", result >> 12);

    let result_str = result_vec.into_iter().map(|x| x.to_string()).collect::<Vec<_>>().join("\n");
    let mut file = fs::File::create("result-rust.txt").unwrap();
    file.write_all(result_str.as_bytes()).unwrap();

    let output = Command::new("/home/jinghao/kcfi-bench/benchmark/bench")
        .output()
        .unwrap();
    println!("{}", std::str::from_utf8(&output.stdout).unwrap());
}

fn main() {
    let args = Args::parse();
    let path = PathBuf::from(args.vmlinux.expect("expecting filename"));
    let file_data = fs::read(path).expect("Could not read file.");
    let slice = file_data.as_slice();
    let file = ElfBytes::<AnyEndian>::minimal_parse(slice).expect("Open ELF");

    let text_shdr = file
        .section_header_by_name(".text")
        .expect("section table should be parseable")
        .expect("file should have a .text section");

    let (section_data, _) = file.section_data(&text_shdr).expect("Parse text data");

    let mut addrs = Vec::new();
    let section_data_len = section_data.len();

    for (offset, _) in section_data.iter().enumerate() {
        // Scan for our nops
        if offset + 5 < section_data_len && is_nop5(&section_data[offset..offset + 5]) {
            addrs.push(offset as u64 + text_shdr.sh_addr);
        }
    }

    let mut attr: ekcfi_attr = unsafe { mem::zeroed() };
    attr.__s1.addrs = addrs.as_ptr();
    attr.__s1.len = addrs.len() as u64;

    // Load table
    unsafe {
        ekcfi_ctl(EKCFI_CMD::EKCFI_LOAD_TBL, &mut attr)
            .or_else(|e| syscall_perror(e, "ekcfi_ctl\0".as_ptr() as *const i8))
            .unwrap();
    }

    println!("eKCFI table loaded");

    let mut kallsyms = HashMap::new();
    for ksym in parse_kallsyms().unwrap() {
        kallsyms.insert(ksym.get_name().to_string(), ksym);
    }

    unsafe {
        attr = mem::zeroed();
        attr.__s2.poke_queue_addr = kallsyms["text_poke_queue"].get_base_addr();
        attr.__s2.poke_finish_addr = kallsyms["text_poke_finish"].get_base_addr();
        attr.__s2.text_mutex_addr = kallsyms["text_mutex"].get_base_addr();
        ekcfi_ctl(EKCFI_CMD::EKCFI_DEFINE_SYM, &mut attr)
            .or_else(|e| syscall_perror(e, "ekcfi_ctl\0".as_ptr() as *const i8))
            .unwrap();
    }

    println!("text poking symbol resolved");

    match &args.mode[..] {
        "trace" => trace(),
        "test" => test(),
        _ => panic!("Invalid mode"),
    }
}
