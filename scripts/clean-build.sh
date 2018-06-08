#!/bin/sh

set -ex

apt-get update -qq
apt-get install -qq -y \
  build-essential \
  debhelper \
  git

apt-get clean

cd /anbox

cleanup() {
  # In cases where anbox comes directly from a checked out Android
  # build environment we miss some symlinks which are present on
  # the host and don't have a valid git repository in that case.
  if [ -d .git ] ; then
    git clean -fdx .
    git reset --hard
  fi
}

cleanup

apt-get install -y build-essential curl devscripts gdebi-core dkms dh-systemd
apt-get install -y $(gdebi --quiet --apt-line ./debian/control)
debuild -us -uc
