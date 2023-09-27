/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI__LINUX_EKCFI_H__
#define _UAPI__LINUX_EKCFI_H__

#include <linux/types.h>

enum ekcfi_cmd {
	EKCFI_LOAD_TBL = 1313ULL,
	EKCFI_ENABLE_ENTRY = 1314ULL,
	EKCFI_ENABLE_ALL = 1315ULL,
	EKCFI_DEFINE_SYM = 1316ULL,
	EKCFI_ATTACH_BPF = 1317ULL,
};

union ekcfi_attr {
	// EKCFI_LOAD_TBL
	__u64 target_addr;

	// EKCFI_ENABLE_ENTRY
	struct {
		__u64 *addrs;
		__u64 len;
	};

	// EKCFI_DEFINE_SYM
	struct {
		__u64 poke_queue_addr;
		__u64 poke_finish_addr;
		__u64 text_mutex_addr;
	};

	// No fields needed for EKCFI_ENABLE_ALL

	// EKCFI_ATTACH_BPF
	__u32 prog_fd;
};

struct ekcfi_ctx {
	__u64 unused;
	__u64 caller;
	__u64 callee;
};

enum ekcfi_action {
	EKCFI_RET_ALLOW = 0U, /* allow */
	EKCFI_RET_PANIC = 1U, /* trigger a panic */
};

#endif /* _UAPI__LINUX_EKCFI_H__ */