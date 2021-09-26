#include <linux/sched.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/atomic.h>
#include <linux/ipc_namespace.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/kallsyms.h>
#include <linux/kprobes.h>
#include <linux/version.h>

#include "deps.h"

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0))

#ifndef CONFIG_KPROBES
# error "Your kernel does not support KProbes, but this is required to compile binder as a kernel module on kernel 5.7 and later"
#endif

typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);

static int dummy_kprobe_handler(struct kprobe *p, struct pt_regs *regs)
{
	return 0;
}

static kallsyms_lookup_name_t get_kallsyms_lookup_name_ptr(void)
{
	struct kprobe probe;
	int ret;
	kallsyms_lookup_name_t addr;

	memset(&probe, 0, sizeof(probe));
	probe.pre_handler = dummy_kprobe_handler;
	probe.symbol_name = "kallsyms_lookup_name";
	ret = register_kprobe(&probe);
	if (ret)
		return NULL;
	addr = (kallsyms_lookup_name_t) probe.addr;
	unregister_kprobe(&probe);

	return addr;
}
#endif

/*
 * On kernel 5.7 and later, kallsyms_lookup_name() can no longer be called from a kernel
 * module for reasons described here: https://lwn.net/Articles/813350/
 * As binder really needs to use kallsysms_lookup_name() to access some kernel
 * functions that otherwise wouldn't be accessible, KProbes are used on later
 * kernels to get the address of kallsysms_lookup_name(). The function is
 * afterwards used just as before. This is a very dirty hack though and the much
 * better solution would be if all the functions that are currently resolved
 * with kallsysms_lookup_name() would get an EXPORT_SYMBOL() annotation to
 * make them directly accessible to kernel modules.
 */
static unsigned long kallsyms_lookup_name_wrapper(const char *name)
{
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0))
	static kallsyms_lookup_name_t func_ptr = NULL;
	if (!func_ptr)
		func_ptr = get_kallsyms_lookup_name_ptr();

	return func_ptr(name);
#else
	return kallsyms_lookup_name(name);
#endif
}


static int (*__close_fd_get_file_ptr)(unsigned int fd, struct file **res) = NULL;

int __close_fd_get_file(unsigned int fd, struct file **res)
{
    if (!__close_fd_get_file_ptr)
		__close_fd_get_file_ptr = kallsyms_lookup_name_wrapper("__close_fd_get_file");
    return __close_fd_get_file_ptr(fd, res);
}

static int (*can_nice_ptr)(const struct task_struct *, const int) = NULL;

int can_nice(const struct task_struct *p, const int nice)
{
	if (!can_nice_ptr)
		can_nice_ptr = kallsyms_lookup_name_wrapper("can_nice");
	return can_nice_ptr(p, nice);
}

static void (*mmput_async_ptr)(struct mm_struct *mm) = NULL;

void mmput_async(struct mm_struct *mm)
{
	if (!mmput_async_ptr)
		mmput_async_ptr = kallsyms_lookup_name_wrapper("mmput_async");
	return mmput_async_ptr(mm);
}

static int (*security_binder_set_context_mgr_ptr)(struct task_struct *mgr) = NULL;

int security_binder_set_context_mgr(struct task_struct *mgr)
{
	if (!security_binder_set_context_mgr_ptr)
		security_binder_set_context_mgr_ptr = kallsyms_lookup_name_wrapper("security_binder_set_context_mgr");
	return security_binder_set_context_mgr_ptr(mgr);
}

static int (*security_binder_transaction_ptr)(struct task_struct *from, struct task_struct *to) = NULL;

int security_binder_transaction(struct task_struct *from, struct task_struct *to)
{
	if (!security_binder_transaction_ptr)
		security_binder_transaction_ptr = kallsyms_lookup_name_wrapper("security_binder_transaction");
	return security_binder_transaction_ptr(from, to);
}

static int (*security_binder_transfer_binder_ptr)(struct task_struct *from, struct task_struct *to) = NULL;

int security_binder_transfer_binder(struct task_struct *from, struct task_struct *to)
{
	if (!security_binder_transfer_binder_ptr)
		security_binder_transfer_binder_ptr = kallsyms_lookup_name_wrapper("security_binder_transfer_binder");
	return security_binder_transfer_binder_ptr(from, to);
}

static int (*security_binder_transfer_file_ptr)(struct task_struct *from, struct task_struct *to, struct file *file) = NULL;

int security_binder_transfer_file(struct task_struct *from, struct task_struct *to, struct file *file)
{
	if (!security_binder_transfer_file_ptr)
		security_binder_transfer_file_ptr = kallsyms_lookup_name_wrapper("security_binder_transfer_file");
	return security_binder_transfer_file_ptr(from, to, file);
}

static int (*task_work_add_ptr)(struct task_struct *task, struct callback_head *work,
		  enum task_work_notify_mode notify) = NULL;

int task_work_add(struct task_struct *task, struct callback_head *work,
		  enum task_work_notify_mode notify)
{
	if (!task_work_add_ptr)
		task_work_add_ptr = kallsyms_lookup_name_wrapper("task_work_add");
	return task_work_add_ptr(task, work, notify);
}

static void (*zap_page_range_ptr)(struct vm_area_struct *, unsigned long, unsigned long) = NULL;

void zap_page_range(struct vm_area_struct *vma, unsigned long address, unsigned long size)
{
	if (!zap_page_range_ptr)
		zap_page_range_ptr = kallsyms_lookup_name_wrapper("zap_page_range");
	zap_page_range_ptr(vma, address, size);
}

static void (*put_ipc_ns_ptr)(struct ipc_namespace *ns) = NULL;

void put_ipc_ns(struct ipc_namespace *ns)
{
	if (!put_ipc_ns_ptr)
		put_ipc_ns_ptr = kallsyms_lookup_name_wrapper("put_ipc_ns");
	put_ipc_ns_ptr(ns);
}

static struct ipc_namespace *init_ipc_ns_ptr = NULL;

struct ipc_namespace *get_init_ipc_ns_ptr(void)
{
	if (!init_ipc_ns_ptr)
		init_ipc_ns_ptr = kallsyms_lookup_name_wrapper("init_ipc_ns");
	return init_ipc_ns_ptr;
}
