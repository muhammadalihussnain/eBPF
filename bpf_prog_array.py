from bcc import BPF
import ctypes as ct

program=r"""

BPF_PROG_ARRAY(syscall,300);

int hello(struct bpf_raw_tracepoint_args *ctx){

int opcode = ctx->args[1];
syscall.call(ctx,opcode);
bpf_trace_printk("Another System Call : %d",opcode);
return 0;
} 

int execve(void *ctx){
bpf_trace_printk("executing Any Program");
return 0;
}

int ignore_func(void *ctx){
return 0;
} 

int timer_function(struct bpf_raw_tracepoint_args *ctx){

if (ctx->args[1]==222){
bpf_trace_printk("creating a time");
}

else if(ctx->args[1]==226){
bpf_trace_printk("deleting Timer");
}

else{
bpf_trace_printk("some other timer functions");
}

return 0;
}
"""
b = BPF(text=program)
b.attach_raw_tracepoint(tp="sys_enter",fn_name="hello")

ignore_function =  b.load_func("ignore_func",   BPF.RAW_TRACEPOINT)
timer_function  =  b.load_func("timer_function",BPF.RAW_TRACEPOINT)
exec_function   =  b.load_func("execve",        BPF.RAW_TRACEPOINT)

prog_array = b.get_table("syscall")

prog_array[ct.c_int(59)]      =  ct.c_int(exec_function.fd)

prog_array[ct.c_int(222)]     =  ct.c_int(timer_function.fd)
prog_array[ct.c_int(223)]     =  ct.c_int(timer_function.fd)
prog_array[ct.c_int(224)]     =  ct.c_int(timer_function.fd)
prog_array[ct.c_int(225)]     =  ct.c_int(timer_function.fd)
prog_array[ct.c_int(226)]     =  ct.c_int(timer_function.fd)



prog_array[ct.c_int(22)]     =  ct.c_int(ignore_function.fd)
prog_array[ct.c_int(23)]     =  ct.c_int(ignore_function.fd)
prog_array[ct.c_int(24)]     =  ct.c_int(ignore_function.fd)
prog_array[ct.c_int(25)]     =  ct.c_int(ignore_function.fd)
prog_array[ct.c_int(26)]     =  ct.c_int(ignore_function.fd)
prog_array[ct.c_int(27)]     =  ct.c_int(ignore_function.fd)
prog_array[ct.c_int(28)]     =  ct.c_int(ignore_function.fd)
prog_array[ct.c_int(29)]     =  ct.c_int(ignore_function.fd)
prog_array[ct.c_int(30)]     =  ct.c_int(ignore_function.fd)
prog_array[ct.c_int(31)]     =  ct.c_int(ignore_function.fd)
prog_array[ct.c_int(32)]     =  ct.c_int(ignore_function.fd)
prog_array[ct.c_int(33)]     =  ct.c_int(ignore_function.fd)
prog_array[ct.c_int(34)]     =  ct.c_int(ignore_function.fd)
prog_array[ct.c_int(35)]     =  ct.c_int(ignore_function.fd)
prog_array[ct.c_int(36)]     =  ct.c_int(ignore_function.fd)
prog_array[ct.c_int(37)]     =  ct.c_int(ignore_function.fd)
b.trace_print()




