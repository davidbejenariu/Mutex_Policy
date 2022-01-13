Implementation of custom Mutex Policy system functions (mtxopen, mtxclose, mtxlock, mtxunlock, mtxlist, mtxgrant - the last two are called by a daemon) in OpenBSD.

Check /sys/kern/sys_generic.c starting from line 1033 for the system functions implementation and /userspace for daemon and tester program.