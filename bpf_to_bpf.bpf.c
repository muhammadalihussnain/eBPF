#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
static __always_inline int get_op_code(struct bpf_raw_tracepoint_args *ctx){
    return ctx->args[1];
}

SEC("raw_tp")
int hello_opcode(struct bpf_raw_tracepoint_args *ctx){

    int op_code = get_op_code(ctx);
    bpf_printk("syscall:        %d",op_code);
    return 0;
}
char LICENSE[] SEC("license")   = "Dual BSD/GPL";