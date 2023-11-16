#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>


struct mkdir_params_t{
    uint64_t UNUSED1;
    uint64_t unused2;
    char *pathname;
};

char License[] SEC("license")="GPL";

SEC("tp/syscalls/sys_enter_mkdir")
int mkdir_path_name(struct mkdir_params_t *pointer){
    bpf_printk("path Name is Given by %s", pointer->pathname);
    return 0;
}