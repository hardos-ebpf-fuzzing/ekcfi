#include <linux/bpf.h>

#include <bpf_helpers.h>

#include <ekcfi.h>

#include "traces.inc" // defines NR_CALLEES and call_map

#define TASK_COMM_LEN 16

const char task_name[] = "uname";

SEC("tracepoint/ekcfi/ekcfi_check")
int ebpf_ekcfi_check(struct ekcfi_ctx *ctx)
{
	char task_comm[16];
	__u32 caller_key;
	__u64 *callees;
	int i;

	// We only want to check for a specific program
	bpf_get_current_comm(task_comm, sizeof(task_comm));
	if (bpf_strncmp(task_comm, sizeof(task_comm), task_name))
		return EKCFI_RET_ALLOW;

	// Grab the call information from call_map
	caller_key = (__u32)(ctx->caller & 0xFFFFFFFF);
	callees = bpf_map_lookup_elem(&call_map, &caller_key);

	// Log and allow if we do not have this callsite information
	if (!callees) {
		bpf_printk("Unknown callsite 0x%llx, target=0x%llx\n",
			ctx->caller, ctx->callee);
		return EKCFI_RET_ALLOW;
	}

	// Check if callee matches
	for (i = 0; i < NR_CALLEES && callees[i]; i++) {
		if (ctx->callee == callees[i])
			return EKCFI_RET_ALLOW;
	}

	// Invalid call
	return EKCFI_RET_PANIC;
}

char _license[] SEC("license") = "GPL";