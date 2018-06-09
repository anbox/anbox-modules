#!/bin/bash

set -ex

KVER=${1:-master}

src_dir="../linux-${KVER}"

if [ "${KVER}" = "master" ]; then
	archive=master.tar.gz
else
	archive="v${KVER}.tar.gz"
fi

if [ ! -d "${src_dir}" ]; then
	wget -O - "https://github.com/torvalds/linux/archive/${archive}" | tar -C ../ -xz
fi

(
cd "$src_dir" || exit 1
make allmodconfig
make prepare
make scripts
)

(
cd ashmem || exit 1
make KERNEL_SRC="../${src_dir}"
)

(
cd binder || exit 1
make KERNEL_SRC="../${src_dir}"
)
