CONFIG_ANDROID_BINDER_IPC ?= m
CONFIG_ANDROID_BINDER_DEVICES ?= binder,hwbinder,vndbinder
CONFIG_ANDROID_BINDER_IPC_32BIT ?= n
CONFIG_ANDROID_BINDER_IPC_SELFTEST ?= n

ifneq ($(KERNELRELEASE),)

# This part of the Makefile is used when called by the kernel build system
# and defines the modules to be built.

TOP_ANDROID_BINDER_MODULES_DIR := $(shell dirname $(lastword $(MAKEFILE_LIST)))

ccflags-y += -I$(TOP_ANDROID_BINDER_MODULES_DIR)	# needed for trace events
ccflags-y += -DCONFIG_ANDROID_BINDER_IPC
ccflags-y += -DCONFIG_ANDROID_BINDER_DEVICES="\"$(CONFIG_ANDROID_BINDER_DEVICES)\""
ifneq ($(filter y m,$(CONFIG_ANDROID_BINDER_IPC_32BIT)),)
ccflags-y += -DCONFIG_ANDROID_BINDER_IPC_32BIT
endif
ifneq ($(filter y,$(CONFIG_ANDROID_BINDER_IPC_SELFTEST)),)
ccflags-y += -DCONFIG_ANDROID_BINDER_IPC_SELFTEST
endif

obj-$(CONFIG_ANDROID_BINDER_IPC) += android-binder.o
android-binder-objs += binder.o binder_alloc.o deps.o
android-binder-$(CONFIG_ANDROID_BINDER_IPC_SELFTEST) += binder_alloc_selftest.o

else # KERNELRELEASE

# This part of the Makefile is used when the 'make' command is runned in the
# base directory of the lttng-modules sources. It sets some environment and
# calls the kernel build system to build the actual modules.

KERNELDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

all: modules

.PHONY: modules
modules:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) V=1 modules

.PHONY: modules_install
modules_install:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules_install

.PHONY: clean
clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean

endif # KERNELRELEASE
