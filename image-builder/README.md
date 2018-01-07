VSSM Image Builder
==================

The contents of this directory are used to build a disk image containing a minimual Linux operating system and the VSSM binary. In order to run it, you should create a `config.json` file (see the README in the root of this project) in this directory and run `build_image.sh`. Note that this script will use sudo (and therefore will prompt for your sudo password, if enabled) in order to setup a loopback device and perform the necessary mounting.

The output of this process will be `build/vssm.img`. This is a raw disk image which you can use to create cloud instances. For example, in AWS this can be written directly to an EBS (e.g. which `dd if=build/vssm.img of=/dev/sdf`) which can then be snapshot in order to create an AMI.

The operating system used for this image is based on [Minimal Linux Live](http://minimal.linux-bg.org/), a collection of shell scripts for building a minimal Linux distirbution. The code in this directory extends it slightly to create a bootable disk image rather than an ISO, and includes an overlay of the VSSM application. This directory also contains a non-default Linux kernel configuration which adds build options necessary for running as a Xen guest operating system (i.e. in order to run in AWS).

The resulting operating system is very small (approximately 9MB). The contents of the OS are the kernel, glibc, and busybox.
