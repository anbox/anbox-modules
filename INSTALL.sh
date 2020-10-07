#!/usr/bin/env bash

# Autoescalate script
anbox-installsh=$(readlink -f "$0")

if [ "$UID" != "0" ] ; then
	sudo exec anbox-installsh
fi

# Installation prompt to make it more user-friendly
while true ; do
	echo -e "Do you want to compile and install Anbox modules? (y/n)"
	read hprompt
	if [ "$hprompt" != "${hprompt#[Yy]}" ] ; then
		install # Call installer function
	elif [ "$hprompt" != "${hprompt#[Nn]}" ] ; then
		echo -e "\nInstallation aborted."
		exit 1
	else
		echo -e "Invalid input $hprompt. Please input either (y)es or (n)o"
	fi
done

install () {
	echo -e "Started installing Anbox modules...\n\n\n"
	# First install the configuration files:
	cp anbox.conf /etc/modules-load.d/
	cp 99-anbox.rules /lib/udev/rules.d/

	# Check if running RHEL kernel fork, and copy the files
	if uname -r | grep -q "el" ; then
		cp -rT el-linux/ashmem /usr/src/anbox-ashmem-1
		cp -rT el-linux/binder /usr/src/anbox-ashmem-1
	fi
	cp -rT ashmem /usr/src/anbox-ashmem-1
	cp -rT binder /usr/src/anbox-binder-1

	# Finally use dkms to build and install:
	dkms install anbox-ashmem/1
	dkms install anbox-binder/1

	# Verify by loading these modules and checking the created devices:
	modprobe ashmem_linux
	modprobe binder_linux
	lsmod | grep -e ashmem_linux -e binder_linux
	ls -alh /dev/binder /dev/ashmem
}
