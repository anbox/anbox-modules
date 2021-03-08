#include <linux/mm.h>
#include <linux/kallsyms.h>
#include <linux/kprobes.h>
#include <linux/version.h>

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0))

#ifndef CONFIG_KPROBES
# error "Your kernel does not support KProbes, but this is required to compile ashmem as a kernel module on kernel 5.7 and later"
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
 * As ashmem really needs to use kallsysms_lookup_name() to access some kernel
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

static int (*shmem_zero_setup_ptr)(struct vm_area_struct *) = NULL;

int shmem_zero_setup(struct vm_area_struct *vma)
{
	if (!shmem_zero_setup_ptr)
		shmem_zero_setup_ptr = kallsyms_lookup_name_wrapper("shmem_zero_setup");
	return shmem_zero_setup_ptr(vma);
}
