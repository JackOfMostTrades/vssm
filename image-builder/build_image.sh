#!/usr/bin/env bash

set -e

VSSM_DIR="$( cd "$(dirname "$0")"; cd ..; pwd -P )"
SRC_DIR="$( cd "$(dirname "$0")" ; pwd -P )"
BUILD_DIR=${SRC_DIR}/build
echo $SRC_DIR

if [[ ! -e ${SRC_DIR}/config.json ]]; then
    echo "You need to create a config.json that will be packaged with VSSM."
    exit 1
fi

# Build vssm
if [[ ! -e ${VSSM_DIR}vssm ]]; then
    cd ${VSSM_DIR}
    make
    if [[ ! -e ${VSSM_DIR}/vssm ]]; then
        echo "Failed to build vssm."
        exit 1
    fi
fi

rm -rf ${BUILD_DIR}
mkdir -p ${BUILD_DIR}
cd ${BUILD_DIR}
tar -Jxvf ${SRC_DIR}/vendor/minimal_linux_live_20-Jan-2017_src.tar.xz
cp ${SRC_DIR}/kernel.config ${BUILD_DIR}/minimal_config/
cp -R ${SRC_DIR}/overlay/* ${BUILD_DIR}/minimal_overlay/rootfs/
cp ${VSSM_DIR}/vssm ${BUILD_DIR}/minimal_overlay/rootfs/opt/vssm/
cp ${SRC_DIR}/config.json ${BUILD_DIR}/minimal_overlay/rootfs/opt/vssm/

# Update the .config
perl -p -i -e 's/^USE_PREDEFINED_KERNEL_CONFIG=false/USE_PREDEFINED_KERNEL_CONFIG=true/' .config
perl -p -i -e 's/^OVERLAY_BUNDLES=.*/OVERLAY_BUNDLES=/' .config

# Run the complete build
bash build_minimal_linux_live.sh


# Load common settings
WORK_DIR=${BUILD_DIR}/work
WORK_SYSLINUX_DIR=`ls -d $WORK_DIR/syslinux/syslinux-*`
SYSROOT=$WORK_DIR/sysroot
ROOTFS=$WORK_DIR/rootfs
KERNEL_INSTALLED=$WORK_DIR/kernel/kernel_installed
ISOIMAGE=$WORK_DIR/isoimage
GLIBC_PREPARED=$WORK_DIR/glibc/glibc_prepared



init_img() {
  rm -f vssm.img
  dd if=/dev/zero bs=50M seek=1 count=0 of=vssm.img

  LOOP_DEVICE_HDD=$(sudo losetup -f)
  if [[ "${LOOP_DEVICE_HDD}" != "/dev/loop0" ]]; then
    echo "Loop device not expected: ${LOOP_DEVICE_HDD}"
    exit 1
  fi
  sudo losetup $LOOP_DEVICE_HDD vssm.img
  sudo fdisk $LOOP_DEVICE_HDD <<EOF || true
o
n
p
1

+20M
a
t
b
n
p
2


w
EOF
  sudo losetup -d $LOOP_DEVICE_HDD
  sudo kpartx -a vssm.img
  sleep 1
  sudo mkfs.vfat /dev/mapper/loop0p1
  sudo mkfs.ext4 /dev/mapper/loop0p2

  mkdir -p ${WORK_DIR}/bootfs_mnt
  mkdir -p ${WORK_DIR}/rootfs_mnt
  sudo mount /dev/mapper/loop0p1 ${WORK_DIR}/bootfs_mnt
  sudo mount /dev/mapper/loop0p2 ${WORK_DIR}/rootfs_mnt
}

cleanup() {
  sudo kpartx -d vssm.img
}

setup_bootfs() {
  # Now we copy the kernel.
  sudo cp $KERNEL_INSTALLED/kernel ${WORK_DIR}/bootfs_mnt/kernel.xz

  # Now we copy the root file system.
  sudo cp $WORK_DIR/rootfs.cpio.xz ${WORK_DIR}/bootfs_mnt/rootfs.xz

  cat <<EOF > ${BUILD_DIR}/syslinux.cfg
PROMPT 1
TIMEOUT 1
DEFAULT vssm

LABEL vssm
        LINUX /kernel.xz
        INITRD /rootfs.xz
EOF
  sudo cp ${BUILD_DIR}/syslinux.cfg ${WORK_DIR}/bootfs_mnt/syslinux.cfg
}

setup_rootfs() {
  sudo mkdir -p ${WORK_DIR}/rootfs_mnt/minimal/rootfs
  sudo mkdir -p ${WORK_DIR}/rootfs_mnt/minimal/work

  sudo cp -rf ${ISOIMAGE}/minimal/rootfs/* ${WORK_DIR}/rootfs_mnt/minimal/rootfs

  # Copy libpthread needed by go runtime
  sudo mkdir -p ${WORK_DIR}/rootfs_mnt/minimal/rootfs/lib/
  echo sudo cp $GLIBC_PREPARED/lib/libpthread.so.0 ${WORK_DIR}/rootfs_mnt/minimal/rootfs/lib/
  sudo cp $GLIBC_PREPARED/lib/libpthread.so.0 ${WORK_DIR}/rootfs_mnt/minimal/rootfs/lib/

  # Extend boot script with autorun functionality
  cp ${BUILD_DIR}/minimal_rootfs/etc/04_bootscript.sh ${WORK_DIR}/04_bootscript.sh
  cat << EOF >> ${WORK_DIR}/04_bootscript.sh
# Autorun functionality
if [ -d /etc/autorun ] ; then
for AUTOSCRIPT in /etc/autorun/*
  do
    if [ -f "\$AUTOSCRIPT" ] && [ -x "\$AUTOSCRIPT" ]; then
      echo -e "Executing \\\\e[32m\$AUTOSCRIPT\\\\e[0m in subshell."
      \$AUTOSCRIPT
    fi
  done
fi
EOF
  sudo cp ${WORK_DIR}/04_bootscript.sh ${WORK_DIR}/rootfs_mnt/minimal/rootfs/etc/
  rm ${WORK_DIR}/04_bootscript.sh
}

install_syslinux() {
  sudo dd if=${WORK_SYSLINUX_DIR}/bios/mbr/mbr.bin of=/dev/loop0
  sudo ${WORK_SYSLINUX_DIR}/bios/linux/syslinux -i /dev/mapper/loop0p1
}

init_img
setup_bootfs
setup_rootfs

sudo umount ${WORK_DIR}/rootfs_mnt
sudo umount ${WORK_DIR}/bootfs_mnt

install_syslinux
cleanup

echo "Successfully built vssm.img"

