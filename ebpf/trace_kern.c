#include <linux/bpf.h>

#include <bpf_helpers.h>

#include <ekcfi.h>

#define TASK_COMM_LEN 16

const char task_name[] = "uname";

SEC("tracepoint/ekcfi/ekcfi_check")
int ebpf_ekcfi_check(struct ekcfi_ctx *ctx)
{
	char task_comm[16];

	bpf_get_current_comm(task_comm, sizeof(task_comm));
	if (bpf_strncmp(task_comm, sizeof(task_comm), task_name))
		return EKCFI_RET_ALLOW;

	bpf_printk("0x%llx => 0x%llx", ctx->caller, ctx->callee);
	return EKCFI_RET_ALLOW;
}

char _license[] SEC("license") = "GPL";