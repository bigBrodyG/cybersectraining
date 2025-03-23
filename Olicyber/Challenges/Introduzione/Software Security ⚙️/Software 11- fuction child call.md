# TERMINAL OUTPUT

```bash
❯ strace -f ./sw-11                   # comando da eseguire 
execve("./sw-11", ["./sw-11"], 0x7ffd11aab768 /* 61 vars */) = 0
brk(NULL)                               = 0x24dd6000
brk(0x24dd6d80)                         = 0x24dd6d80
arch_prctl(ARCH_SET_FS, 0x24dd6380)     = 0
uname({sysname="Linux", nodename="archlinux", ...}) = 0
readlink("/proc/self/exe", "/home/user/Downloads/sw-11", 4096) = 26
brk(0x24df7d80)                         = 0x24df7d80
brk(0x24df8000)                         = 0x24df8000
mprotect(0x4ac000, 4096, PROT_READ)     = 0
fstat(1, {st_mode=S_IFCHR|0620, st_rdev=makedev(0x88, 0), ...}) = 0
write(1, "[parent] \342\234\205 Spawning child proc"..., 36[parent] Spawning child process
) = 36
clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0x24dd6650) = 12727
strace: Process 12727 attached
[pid 12726] wait4(-1,  <unfinished ...>
[pid 12727] write(1, "[child ] \342\234\250 Executing open(FLAG"..., 37[child ] ✨ Executing open(FLAG)...
) = 37
[pid 12727] ✅ --> openat(AT_FDCWD, "flag{5a11b5a6}", O_RDONLY) = -1 ENOENT (No such file or directory)
[pid 12727] exit_group(0)               = ?
[pid 12727] +++ exited with 0 +++
<... wait4 resumed>NULL, 0, NULL)       = 12727
--- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=12727, si_uid=1000, si_status=0, si_utime=0, si_stime=0} ---
write(1, "[parent] \342\234\205 Child exited\n", 26[parent] ✅ Child exited
) = 26
exit_group(0)                           = ?
+++ exited with 0 +++
```

## flag

flag{5a11b5a6}
