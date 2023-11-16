#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

SEC("tp/syscalls/sys_enter_execve")
int handle_execve(void *ctx)
{
    bpf_printk("execution of system call \n");
    return 0;
}

char LICENSE[] SEC("license") = "GPL";