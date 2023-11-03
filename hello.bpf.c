#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>


int counter=0;

SEC("xdp")

int hello(void *ctx){
    bpf_printk("This is packet Number   : %d",counter++);
    return XDP_PASS;
}
char LICENSE[] SEC("license")   = "Dual BSD/GPL";

