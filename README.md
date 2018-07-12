[![Build Status](https://travis-ci.org/anbox/anbox-modules.svg?branch=master)](https://travis-ci.org/anbox/anbox-modules)

# Anbox Kernel Modules

This repository contains the kernel modules necessary to run the Anbox
Android container runtime. They're split out of the original Anbox
repository to make packaging in various Linux distributions easier.

# Install Instruction

You need to have `dkms` and linux-headers on your system. You can install them by
`sudo apt install dkms` or `sudo yum install dkms` (`dkms` is available in epel repo
for CentOS).

Package name for linux-headers varies on different distributions, e.g.
`linux-headers-generic` (Ubuntu), `linux-headers-amd64` (Debian),
`kernel-devel` (CentOS, Fedora), `kernel-default-devel` (openSUSE).

* First install the configuration files:

  ```
  $ sudo cp anbox.conf /etc/modules-load.d/
  $ sudo cp 99-anbox.rules /lib/udev/rules.d/
  ```

* Then copy the module sources to `/usr/src/`:

  ```
  $ sudo cp -rT ashmem /usr/src/anbox-ashmem-1
  $ sudo cp -rT binder /usr/src/anbox-binder-1
  ```

* Finally use `dkms` to build and install:

  ```
  $ sudo dkms install anbox-ashmem/1
  $ sudo dkms install anbox-binder/1
  ```

You can verify by loading these modules and checking the created devices:

```
$ sudo modprobe ashmem_linux
$ sudo modprobe binder_linux
$ lsmod | grep -e ashmem_linux -e binder_linux
$ ls -alh /dev/binder /dev/ashmem
```

You are expected to see output like:

```
binder_linux          114688  0
ashmem_linux           16384  0
crw-rw-rw- 1 root root  10, 55 Jun 19 16:30 /dev/ashmem
crw-rw-rw- 1 root root 511,  0 Jun 19 16:30 /dev/binder
```
