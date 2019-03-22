#!/bin/bash
/root/qhw/femu/build-femu/x86_64-softmmu/qemu-system-x86_64 \
	-name "qhwVM" \
	-m 32G \
	-smp 32 \
	--enable-kvm \
	-net nic,macaddr=52:54:00:17:21:72 -net tap,ifname=tap0,script=/var/lib/libvirt/images/qemu-ifup.sh,downscript=no \
	-device virtio-scsi-pci,id=scsi0 \
	-hda /mnt/sdc/qhw/images/qhwImage.qcow2 \
	-hdb /home/qhw/VMimages/backdrive.raw \
	-drive file=/home/qhw/VMimages/vssd1.raw,if=none,aio=threads,format=raw,id=id0 \
	-device nvme,drive=id0,serial=serial0,id=nvme0,namespaces=1,lver=1,lmetasize=16,ll2pmode=0,nlbaf=5,lba_index=3,mdts=10,lnum_ch=32,lnum_lun=4,lnum_pln=2,lsec_size=4096,lsecs_per_pg=4,lpgs_per_blk=512,ldebug=0,femu_mode=0 \
	-qmp unix:./qmp-sock,server,nowait \
	-k en-us \
	-sdl

