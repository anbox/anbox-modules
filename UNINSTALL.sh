#!/usr/bin/env bash

# First use dkms to remove the modules:
sudo dkms remove anbox-ashmem/1
sudo dkms remove anbox-binder/1

# Then remove the module sources from /usr/src/:
sudo rm -rf /usr/src/anbox-ashmem-1
sudo rm -rf /usr/src/anbox-binder-1

# Finally remove the configuration files:
sudo rm -f /etc/modules-load.d/anbox.conf
sudo rm -f /lib/udev/rules.d/99-anbox.rules

# Verify remove by trying to load the modules and checking the created devices:
failed_checks=0
if sudo modprobe ashmem_linux > /dev/null 2>&1; then
    failed_checks=1
else
    failed_checks=0
fi

if sudo modprobe binder_linux > /dev/null 2>&1; then
    failed_checks=1
else
    failed_checks=0
fi

if lsmod | grep -e ashmem_linux -e binder_linux > /dev/null 2>&1; then
    failed_checks=1
else
    failed_checks=0
fi

if ls -alh /dev/binder /dev/ashmem > /dev/null 2>&1; then
    failed_checks=1
else
    failed_checks=0
fi

if [ $failed_checks == 1 ]; then
    echo "Please restart your device and rerun this script to verify changes"
else
    echo "Modules not installed"
fi