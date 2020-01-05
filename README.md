# IBS-based Support for User-Level-Micro-Thread (ULMT) Technology

The *User-Level-Micro-Thread* technology requires to be supported by both the hardware interrupts and related kernel facilities to make it possible for OS-threads to slide out from their execution flow in a safe manner.

This Linux kernel module is intended to provide the capability to perform *Control-Flow-Variation* of threads managed by the Linux operating system upon the occurrence of *Instruction-Based-Sampling* interrupts. This is achieved by giving control to a callback-function appositely registered by the threads that are carrying on the execution of ULMT-based application's tasks.

This is the case of *pthreads* (POSIX Threads) which can register theirself to the device provided by this module in order to receive periodic---user-defined time interval---interrupts from IBS hardware support.

## Compilation and Installation

To compile and install the module, use the following commands:
```sh
>  make
>  sudo insmod ibs_core.ko
```

To remove the module and clean the directory from object files, use the following commands:
```sh
>  sudo rmmod ibs_core
>  make clean
```

## Hints

Unless you are already using ULMT-based runtimes, such as the one included with <a href="https://github.com/HPDCS/ULMT-OpenMP-GCC">ULMT GNU OpenMP</a>, you have to code from scratch your own ULMT environemnt as well as the stub for registering/deregistering threads from IBS module.