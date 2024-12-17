#!/bin/bash
# Script outline to install and build kernel.
# Author: Siddhant Jajoo.

set -e
set -u

OUTDIR=/tmp/aeld
KERNEL_REPO=git://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git
KERNEL_VERSION=v5.1.10
BUSYBOX_VERSION=1_33_1
FINDER_APP_DIR=$(realpath $(dirname $0))
ARCH=arm64
CROSS_COMPILE=aarch64-none-linux-gnu-
PROJECT_DIR=${PWD}

if [ $# -lt 1 ]
then
	echo "Using default directory ${OUTDIR} for output"
else
	OUTDIR=$1
	echo "Using passed directory ${OUTDIR} for output"
fi

mkdir -p ${OUTDIR}

cd "$OUTDIR"
if [ ! -d "${OUTDIR}/linux-stable" ]; then
    #Clone only if the repository does not exist.
	echo "CLONING GIT LINUX STABLE VERSION ${KERNEL_VERSION} IN ${OUTDIR}"
	git clone ${KERNEL_REPO} --depth 1 --single-branch --branch ${KERNEL_VERSION}
fi
if [ ! -e ${OUTDIR}/linux-stable/arch/${ARCH}/boot/Image ]; then
    cd linux-stable
    echo "Checking out version ${KERNEL_VERSION}"
    git checkout ${KERNEL_VERSION}
    git restore .    
    #git apply -v ~/cu-ecen-aeld/finder-app/dtc-lexer.l.patch

    # TODO: Add your kernel build steps here
    make ARCH=arm64 CROSS_COMPILE=aarch64-none-linux-gnu- mrproper
    make ARCH=arm64 CROSS_COMPILE=aarch64-none-linux-gnu- defconfig
    make -j4 ARCH=arm64 CROSS_COMPILE=aarch64-none-linux-gnu- all
    make ARCH=arm64 CROSS_COMPILE=aarch64-none-linux-gnu- modules
    make ARCH=arm64 CROSS_COMPILE=aarch64-none-linux-gnu- dtbs 
fi

echo "Adding the Image in outdir"
cp ${OUTDIR}/linux-stable/arch/${ARCH}/boot/Image ${OUTDIR}

echo "Creating the staging directory for the root filesystem"
cd "$OUTDIR"
if [ -d "${OUTDIR}/rootfs" ]
then
	echo "Deleting rootfs directory at ${OUTDIR}/rootfs and starting over"
    sudo rm  -rf ${OUTDIR}/rootfs
fi

# TODO: Create necessary base directories
mkdir -p "$OUTDIR/rootfs"
cd "$OUTDIR/rootfs"
mkdir -p bin dev etc home lib lib64 proc sbin sys tmp usr var 
mkdir -p usr/bin usr/lib usr/sbin
mkdir -p var/log

cd "$OUTDIR"
if [ ! -d "${OUTDIR}/busybox" ]
then
git clone git://busybox.net/busybox.git
    cd busybox
    git checkout ${BUSYBOX_VERSION}
    # TODO:  Configure busybox
else
    cd busybox
fi

if [ ! -e "${OUTDIR}/rootfs/bin/busybox" ]
then
# TODO: Make and install busybox
make distclean
make defconfig
make ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE}
make CONFIG_PREFIX=${OUTDIR}/rootfs ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE} install
fi

echo "Library dependencies"
cd "$OUTDIR/rootfs"
${CROSS_COMPILE}readelf -a bin/busybox | grep "program interpreter"
${CROSS_COMPILE}readelf -a bin/busybox | grep "Shared library"

# TODO: Add library dependencies to rootfs

# use readelf on busybox binary to determine program interpreter and shared library dependencies;
# Copy from cross-compile toolchain and place in /lib64
cp $(dirname $(which 'aarch64-none-linux-gnu-gcc'))/../aarch64-none-linux-gnu/libc/lib/ld-linux-aarch64.so.1 $OUTDIR/rootfs/lib
cp $(dirname $(which 'aarch64-none-linux-gnu-gcc'))/../aarch64-none-linux-gnu/libc/lib64/libc.so.6 $OUTDIR/rootfs/lib64
cp $(dirname $(which 'aarch64-none-linux-gnu-gcc'))/../aarch64-none-linux-gnu/libc/lib64/libm.so.6 $OUTDIR/rootfs/lib64
cp $(dirname $(which 'aarch64-none-linux-gnu-gcc'))/../aarch64-none-linux-gnu/libc/lib64/libresolv.so.2 $OUTDIR/rootfs/lib64

# TODO: Make device nodes
cd "$OUTDIR/rootfs"
sudo mknod -m 666 dev/null c 1 3
sudo mknod -m 666 dev/console c 5 1

# TODO: Clean and build the writer utility
cd $PROJECT_DIR
make clean
make CROSS_COMPILE=$CROSS_COMPILE
cp writer "$OUTDIR/rootfs/home/writer"
chmod +x "$OUTDIR/rootfs/home/writer"

# TODO: Copy the finder related scripts and executables to the /home directory
# on the target rootfs
cp finder.sh "$OUTDIR/rootfs/home/finder.sh"
chmod +x "$OUTDIR/rootfs/home/finder.sh"
cp finder-test.sh "$OUTDIR/rootfs/home/finder-test.sh"
chmod +x "$OUTDIR/rootfs/home/finder-test.sh"
mkdir -p "$OUTDIR/rootfs/home/conf"
cp conf/assignment.txt "$OUTDIR/rootfs/home/conf/assignment.txt"
cp conf/username.txt "$OUTDIR/rootfs/home/conf/username.txt"
cp autorun-qemu.sh "$OUTDIR/rootfs/home/autorun-qemu.sh"
chmod +x "$OUTDIR/rootfs/home/autorun-qemu.sh"

# TODO: Chown the root directory
sudo chown -R root:root "$OUTDIR/rootfs"

# TODO: Create initramfs.cpio.gz
cd "$OUTDIR/rootfs"
find . | cpio -H newc -ov --owner root:root > ${OUTDIR}/initramfs.cpio
cd ..
gzip -f initramfs.cpio
