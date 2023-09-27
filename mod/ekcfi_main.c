/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <linux/bsearch.h>
#include <linux/capability.h>
#include <linux/compiler.h>
#include <linux/filter.h>
#include <linux/memory.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/panic.h>
#include <linux/percpu-defs.h>
#include <linux/preempt.h>
#include <linux/proc_fs.h>
#include <linux/rcupdate.h>
#include <linux/spinlock.h>
#include <linux/vmalloc.h>

#include <asm/text-patching.h>

#include "ekcfi.h"

MODULE_AUTHOR("Jinghao Jia");
MODULE_LICENSE("GPL");

#define EKCFI_FILE_NAME "ekcfi"

#define EKCFI_PATCH_SIZE 5

struct ekcfi_tbl {
	u64 *ekcfi_data;
	u64 len;
};

static struct ekcfi_tbl __rcu *ekcfi_tbl __read_mostly;
static DEFINE_SPINLOCK(ekcfi_tbl_lock);

static DEFINE_PER_CPU(bool, in_ekcfi_check);

// nopl   0x8(%rax,%rax,1)
static const unsigned char ekcfi_nop[] = { 0x0f, 0x1f, 0x44, 0x00, 0x08 };

// Kernel text poking APIs we have to use intrusively
static void(__rcu *ekcfi_text_poke_queue)(void *, const void *, size_t,
					  const void *) __read_mostly;
static void(__rcu *ekcfi_text_poke_finish)(void) __read_mostly;
// points to text_mutex, thus safe
static struct mutex __rcu *ekcfi_text_mutex __read_mostly;

// Support single BPF prog for now
static struct bpf_prog __rcu *ekcfi_prog;

// Trampoline
extern void ekcfi_tramp_64(void);

static inline const char *ekcfi_nop_replace(void)
{
	return ekcfi_nop;
}

static inline const char *ekcfi_call_replace(unsigned long addr,
						 unsigned long target)
{
	return text_gen_insn(CALL_INSN_OPCODE, (void *)addr, (void *)target);
}

static inline void __ekcfi_make_call(unsigned long addr, unsigned long target)
{
	const char *new;
	new = ekcfi_call_replace(addr, target);

	rcu_dereference(ekcfi_text_poke_queue)((void *)addr, new,
						   EKCFI_PATCH_SIZE, NULL);
	rcu_dereference(ekcfi_text_poke_finish)();
}

static inline void __ekcfi_make_nop(unsigned long addr)
{
	const char *new;
	new = ekcfi_nop_replace();

	rcu_dereference(ekcfi_text_poke_queue)((void *)addr, new,
						   EKCFI_PATCH_SIZE, NULL);
	rcu_dereference(ekcfi_text_poke_finish)();
}

static inline void ekcfi_make_call(unsigned long addr, unsigned long target)
{
	mutex_lock(rcu_dereference(ekcfi_text_mutex));
	__ekcfi_make_call(addr, target);
	mutex_unlock(rcu_dereference(ekcfi_text_mutex));
}

static inline void ekcfi_make_nop(unsigned long addr)
{
	mutex_lock(rcu_dereference(ekcfi_text_mutex));
	__ekcfi_make_nop(addr);
	mutex_unlock(rcu_dereference(ekcfi_text_mutex));
}

static int ekcfi_load_tbl(u64 *addrs, u64 len)
{
	int ret = 0;
	unsigned long flags;
	struct ekcfi_tbl *et;

	spin_lock_irqsave(&ekcfi_tbl_lock, flags);

	// At this point, prevent table from changing after init
	if (rcu_access_pointer(ekcfi_tbl)) {
		ret = -EPERM;
		goto out_unlock;
	}

	et = kzalloc(sizeof(*et), GFP_KERNEL);
	if (!et) {
		ret = -ENOMEM;
		goto out_unlock;
	}

	et->ekcfi_data = vzalloc(sizeof(u64) * len);
	if (!et->ekcfi_data) {
		ret = -ENOMEM;
		goto out_vmalloc_err;
	}

	if (copy_from_user(et->ekcfi_data, addrs, sizeof(u64) * len)) {
		ret = -EFAULT;
		goto out_copy_err;
	}
	et->len = len;

	rcu_assign_pointer(ekcfi_tbl, et);

	spin_unlock_irqrestore(&ekcfi_tbl_lock, flags);

	return 0;

out_copy_err:
	vfree(et->ekcfi_data);
out_vmalloc_err:
	kfree(et);
out_unlock:
	spin_unlock_irqrestore(&ekcfi_tbl_lock, flags);
	return ret;
}

static int ekcfi_cmp_addr(const void *a, const void *b)
{
	u64 lhs = *(u64 *)a;
	u64 rhs = *(u64 *)b;

	if (lhs < rhs)
		return -1;
	else if (lhs > rhs)
		return 1;
	else
		return 0;
}

static int ekcfi_enable_entry(u64 addr)
{
	u64 target_addr;
	u64 *search_result;
	int ret = 0;
	struct ekcfi_tbl *et;

	rcu_read_lock();
	et = rcu_dereference(ekcfi_tbl);

	if (!et) {
		ret = -EINVAL;
		goto out;
	}

	if (!rcu_access_pointer(ekcfi_text_poke_queue) &&
		!rcu_access_pointer(ekcfi_text_poke_finish) &&
		!rcu_access_pointer(ekcfi_text_mutex)) {
		ret = -EINVAL;
		goto out;
	}

	search_result = bsearch(&addr, et->ekcfi_data, et->len, sizeof(u64),
				ekcfi_cmp_addr);

	if (!search_result) {
		ret = -EINVAL;
		goto out;
	}

	target_addr = *search_result;

	ekcfi_make_call(target_addr, (unsigned long)ekcfi_tramp_64);

out:
	rcu_read_unlock();
	return ret;
}

static int ekcfi_enable_all(void)
{
	int i;
	int ret = 0;
	struct ekcfi_tbl *et;

	rcu_read_lock();
	et = rcu_dereference(ekcfi_tbl);

	if (!et) {
		ret = -EINVAL;
		goto out;
	}

	if (!rcu_access_pointer(ekcfi_text_poke_queue) &&
		!rcu_access_pointer(ekcfi_text_poke_finish) &&
		!rcu_access_pointer(ekcfi_text_mutex)) {
		ret = -EINVAL;
		goto out;
	}

	for (i = 0; i < et->len; i++)
		ekcfi_make_call(et->ekcfi_data[i], (unsigned long)ekcfi_tramp_64);

out:
	rcu_read_unlock();
	return ret;
}

static int ekcfi_define_sym(u64 poke_queue_addr, u64 poke_finish_addr,
				u64 text_mutex_addr)
{
	int ret = 0;
	unsigned long flags;

	spin_lock_irqsave(&ekcfi_tbl_lock, flags);

	if (rcu_access_pointer(ekcfi_text_poke_queue) ||
		rcu_access_pointer(ekcfi_text_poke_finish) ||
		rcu_access_pointer(ekcfi_text_mutex)) {
		ret = -EPERM;
		goto out_unlock;
	}

	rcu_assign_pointer(ekcfi_text_poke_queue, poke_queue_addr);
	rcu_assign_pointer(ekcfi_text_poke_finish, poke_finish_addr);
	rcu_assign_pointer(ekcfi_text_mutex, text_mutex_addr);

out_unlock:
	spin_unlock_irqrestore(&ekcfi_tbl_lock, flags);
	return ret;
}

static int ekcfi_attach_bpf(u32 prog_fd)
{
	int ret = 0;
	unsigned long flags;
	struct bpf_prog *prog;

	spin_lock_irqsave(&ekcfi_tbl_lock, flags);

	// For now do not allow updating attached prog
	if (rcu_access_pointer(ekcfi_prog)) {
		ret = -EPERM;
		goto out_unlock;
	}

	// We are going to hold this refcnt
	prog = bpf_prog_get_type_dev(prog_fd, BPF_PROG_TYPE_TRACEPOINT, false);
	if (IS_ERR(prog)) {
		ret = PTR_ERR(prog);
		goto out_unlock;
	}

	rcu_assign_pointer(ekcfi_prog, prog);

out_unlock:
	spin_unlock_irqrestore(&ekcfi_tbl_lock, flags);
	return ret;
}

static long ekcfi_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	union ekcfi_attr kattr = { 0 };
	union ekcfi_attr *attr = (union ekcfi_attr *)arg;
	int ret;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (copy_from_user(&kattr, attr, sizeof(kattr)))
		return -EFAULT;

	switch (cmd) {
	case EKCFI_LOAD_TBL:
		ret = ekcfi_load_tbl(kattr.addrs, kattr.len);
		break;

	case EKCFI_ENABLE_ENTRY:
		ret = ekcfi_enable_entry(kattr.target_addr);
		break;

	case EKCFI_ENABLE_ALL:
		ret = ekcfi_enable_all();
		break;

	case EKCFI_DEFINE_SYM:
		ret = ekcfi_define_sym(kattr.poke_queue_addr,
					   kattr.poke_finish_addr,
					   kattr.text_mutex_addr);
		break;

	case EKCFI_ATTACH_BPF:
		ret = ekcfi_attach_bpf(kattr.prog_fd);
		break;

	default:
		ret = -EINVAL;
		break;
	}

	return ret;
}

int __nocfi noinstr ekcfi_check(u64 caller, u64 callee)
{
	struct ekcfi_ctx ctx;
	struct bpf_prog *prog;
	unsigned ret;

	if (!in_task() || !current->pid)
		return 0;

	preempt_disable();

	// Prevent recursion
	if (this_cpu_read(in_ekcfi_check))
		goto out_preempt_enable;

	this_cpu_write(in_ekcfi_check, true);

	rcu_read_lock();

	// Make sure we do have a prog to run
	prog = rcu_dereference(ekcfi_prog);
	if (!prog)
		goto out_unlock;

	ctx.caller = caller;
	ctx.callee = callee;

	// Call eBPF prog
	// Not need for migrate_disable -- we already have preempt_disable
	ret = prog->bpf_func(&ctx, prog->insnsi);

	// If we need to panic, we do it before clearing in_ekcfi_check to
	// prevent entering this hook again during panic
	if (unlikely(ret == EKCFI_RET_PANIC))
		panic("eKCFI failure at 0x%llx (target: 0x%llx)\n", caller, callee);

out_unlock:
	rcu_read_unlock();
	this_cpu_write(in_ekcfi_check, false);
out_preempt_enable:
	preempt_enable();
	return 0;
}

// file_operations for proc-fs
static const struct proc_ops ekcfi_fops = {
	.proc_flags = PROC_ENTRY_PERMANENT,
	.proc_ioctl = ekcfi_ioctl
};

int __init ekcfi_init(void)
{
	if (!proc_create(EKCFI_FILE_NAME, 0600, NULL, &ekcfi_fops))
		return -ENOMEM;

	return 0;
}

void __exit ekcfi_exit(void)
{
	remove_proc_entry(EKCFI_FILE_NAME, NULL);
	// TODO: Cleanup used resources
}

// Register init and exit funtions
module_init(ekcfi_init);
module_exit(ekcfi_exit);