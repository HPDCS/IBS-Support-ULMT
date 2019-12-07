# IBS-based Support for User-Level-Micro-Thread (ULMT) Technology

The *User-Level-Micro-Thread* technology requires to be supported by both the hardware interrupts and related kernel facilities to make it possible for OS-threads to slide out from their execution flow in a safe manner.

This Linux kernel module is intended to provide the capability to perform *Control-Flow-Variation* of threads managed by the Linux operating system upon the occurrence of *Instruction-Based-Sampling* interrupts. This is achieved by giving control to a callback-function appositely registered by the threads that are carrying on the execution of ULMT-based application's tasks.

To compile and install the module use the following commands:
1. **make**
2. **sudo insmod ibs_core.ko**

To remove the module and clean its directory use the following commands:
1. **sudo rmmod ibs_core**
2. **make clean**