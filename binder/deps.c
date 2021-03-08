#include <linux/sched.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/atomic.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/kallsyms.h>
#include <linux/kprobes.h>
#include <linux/version.h>

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


static struct vm_struct *(*get_vm_area_ptr)(unsigned long, unsigned long) = NULL;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
static void (*zap_page_range_ptr)(struct vm_area_struct *, unsigned long, unsigned long) = NULL;
#else
static void (*zap_page_range_ptr)(struct vm_area_struct *, unsigned long, unsigned long, struct zap_details *) = NULL;
#endif
static int (*map_kernel_range_noflush_ptr)(unsigned long start, unsigned long size, pgprot_t prot, struct page **pages) = NULL;
static void (*unmap_kernel_range_ptr)(unsigned long, unsigned long) = NULL;
static struct files_struct *(*get_files_struct_ptr)(struct task_struct *) = NULL;
static void (*put_files_struct_ptr)(struct files_struct *) = NULL;
static struct sighand_struct *(*__lock_task_sighand_ptr)(struct task_struct *, unsigned long *) = NULL;
static int (*__alloc_fd_ptr)(struct files_struct *files, unsigned start, unsigned end, unsigned flags) = NULL;
static void (*__fd_install_ptr)(struct files_struct *files, unsigned int fd, struct file *file) = NULL;
static int (*__close_fd_ptr)(struct files_struct *files, unsigned int fd) = NULL;
static int (*can_nice_ptr)(const struct task_struct *, const int) = NULL;
static int (*security_binder_set_context_mgr_ptr)(struct task_struct *mgr) = NULL;
static int (*security_binder_transaction_ptr)(struct task_struct *from, struct task_struct *to) = NULL;
static int (*security_binder_transfer_binder_ptr)(struct task_struct *from, struct task_struct *to) = NULL;
static int (*security_binder_transfer_file_ptr)(struct task_struct *from, struct task_struct *to, struct file *file) = NULL;

struct vm_struct *get_vm_area(unsigned long size, unsigned long flags)
{
	if (!get_vm_area_ptr)
		get_vm_area_ptr = kallsyms_lookup_name_wrapper("get_vm_area");
	return get_vm_area_ptr(size, flags);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
void zap_page_range(struct vm_area_struct *vma, unsigned long address, unsigned long size)
#else
void zap_page_range(struct vm_area_struct *vma, unsigned long address, unsigned long size, struct zap_details *details)
#endif
{
	if (!zap_page_range_ptr)
		zap_page_range_ptr = kallsyms_lookup_name_wrapper("zap_page_range");
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
	zap_page_range_ptr(vma, address, size);
#else
	zap_page_range_ptr(vma, address, size, details);
#endif
}

int map_kernel_range_noflush(unsigned long start, unsigned long size, pgprot_t prot, struct page **pages)
{
	if (!map_kernel_range_noflush_ptr)
		map_kernel_range_noflush_ptr = kallsyms_lookup_name_wrapper("map_kernel_range_noflush");
	return map_kernel_range_noflush_ptr(start, size, prot, pages);
}

void unmap_kernel_range(unsigned long addr, unsigned long size)
{
	if (!unmap_kernel_range_ptr)
		unmap_kernel_range_ptr = kallsyms_lookup_name_wrapper("unmap_kernel_range");
	unmap_kernel_range_ptr(addr, size);
}

struct files_struct *get_files_struct(struct task_struct *task)
{
	if (!get_files_struct_ptr)
		get_files_struct_ptr = kallsyms_lookup_name_wrapper("get_files_struct");
	return get_files_struct_ptr(task);
}

void put_files_struct(struct files_struct *files)
{
	if (!put_files_struct_ptr)
		put_files_struct_ptr = kallsyms_lookup_name_wrapper("put_files_struct");
	put_files_struct_ptr(files);
}

struct sighand_struct *__lock_task_sighand(struct task_struct *tsk, unsigned long *flags)
{
	if (!__lock_task_sighand_ptr)
		__lock_task_sighand_ptr = kallsyms_lookup_name_wrapper("__lock_task_sighand");
	return __lock_task_sighand_ptr(tsk, flags);
}

int __alloc_fd(struct files_struct *files, unsigned start, unsigned end, unsigned flags)
{
	if (!__alloc_fd_ptr)
		__alloc_fd_ptr = kallsyms_lookup_name_wrapper("__alloc_fd");
	return __alloc_fd_ptr(files, start, end, flags);
}

void __fd_install(struct files_struct *files, unsigned int fd, struct file *file)
{
	if (!__fd_install_ptr)
		__fd_install_ptr = kallsyms_lookup_name_wrapper("__fd_install");
	__fd_install_ptr(files, fd, file);
}

int __close_fd(struct files_struct *files, unsigned int fd)
{
	if (!__close_fd_ptr)
		__close_fd_ptr = kallsyms_lookup_name_wrapper("__close_fd_ptr");
	return __close_fd_ptr(files, fd);
}

int can_nice(const struct task_struct *p, const int nice)
{
	if (!can_nice_ptr)
		can_nice_ptr = kallsyms_lookup_name_wrapper("can_nice");
	return can_nice_ptr(p, nice);
}

int security_binder_set_context_mgr(struct task_struct *mgr)
{
	if (!security_binder_set_context_mgr_ptr)
		security_binder_set_context_mgr_ptr = kallsyms_lookup_name_wrapper("security_binder_set_context_mgr");
	return security_binder_set_context_mgr_ptr(mgr);
}

int security_binder_transaction(struct task_struct *from, struct task_struct *to)
{
	if (!security_binder_transaction_ptr)
		security_binder_transaction_ptr = kallsyms_lookup_name_wrapper("security_binder_transaction");
	return security_binder_transaction_ptr(from, to);
}

int security_binder_transfer_binder(struct task_struct *from, struct task_struct *to)
{
	if (!security_binder_transfer_binder_ptr)
		security_binder_transfer_binder_ptr = kallsyms_lookup_name_wrapper("security_binder_transfer_binder");
	return security_binder_transfer_binder_ptr(from, to);
}

int security_binder_transfer_file(struct task_struct *from, struct task_struct *to, struct file *file)
{
	if (!security_binder_transfer_file_ptr)
		security_binder_transfer_file_ptr = kallsyms_lookup_name_wrapper("security_binder_transfer_file");
	return security_binder_transfer_file_ptr(from, to, file);
}
