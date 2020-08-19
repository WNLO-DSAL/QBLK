# QBLK

## QBLK Introduction

QBLK is a device driver for Open Channel SSDs based on linux kernel 4.16.0. QBLK is modified from pblk, which is an Open Channel SSD device driver in linux kernel.

By using 4 techniques:

* Multi-queue Based Buffering
* Per-channel Based Address Management
* Lock-free Address Mapping
* Fine-grained Draining

QBLK can achieve good performance under heavy-threaded workloads.

For more information, please refer to our paper "QBLK: Towards Fully Exploiting the Parallelism of Open-Channel SSDs" in [DATE 2019](https://date-conference.com/).

```
Qin, Hongwei, et al. "QBLK: Towards Fully Exploiting the Parallelism of Open-Channel SSDs." 2019 Design, Automation & Test in Europe Conference & Exhibition (DATE). IEEE, 2019.
```


## Usage

1. As we've mentioned before, QBLK is an Open Channel SSD(OCSSD) driver. So, your server should have an Open Channel SSD which supports [Open Channel SSD specification 1.2](https://openchannelssd.readthedocs.io/en/latest/specification/).

If you're like me who doesn't have an Open Channel SSD hardware, you can use [FEMU](https://github.com/ucare-uchicago/femu) to emulate an Open Channel SSD for your QEMU virtual machine.

`./scripts/qblk/femu/startFemu.sh` contains an example script to run FEMU.

2. On the server which has an Open Channel SSD or emulated OCSSD, download the linux kernel source version 4.16.0. Copy our code into the corresponding folder.

QBLK relys on the lightNVM infrastructure, but we changed some interface between lightNVM and device driver. So, you may need to overwrite some files. (e.g. core.c)

3. If you are using FEMU, do the additional tweaks described in [FEMU's github](https://github.com/ucare-uchicago/femu).

4. Build the kernel. Don't forget to enable lightNVM(NVM=y) and disable pblk(NVM_PBLK=n). Restart and run the new kernel.

5. Build QBLK.

```
# cd drivers/qblk
# make
```

6. Run QBLK. The shell script "install" in QBLK's folder shows an example of using QBLK.

7. Run benchmark. You may want to use fio to measure QBLK's performance.

`./scripts/qblk/fio/fioqblkdev_randwrite` contains an example fio job file to test QBLK.

You can use the following script to run fio under 32 threads.

```
fio -numjobs=32 fioqblkdev_randwrite
```

## QBLKe introduction

QBLK express (QBLKe) is optimized from QBLK. QBLKe uses a technique called load adaptive ring buffer to enhance the driver's performance when there are only a small number of IO threads.

Enjoy :)

## ToDoList

1. Add copywrite.

2. Implement discard and flush command.

3. Make GC more efficient.

