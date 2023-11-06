from bcc import BPF
import ctypes as ct
program = r"""
struct data_msg_t{
char message[12];
};
BPF_HASH(config, u32, struct data_msg_t);
BPF_PERF_OUTPUT(output);
struct data_t {
int pid;
int uid;
char command[16];
char message[12];
};
int hello_my_world(void *ctx){
struct data_t data={};
struct data_msg_t *p;
char message[12]="hello world";
data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
data.pid = bpf_get_current_pid_tgid() >> 32;
bpf_get_current_comm(&data.command, sizeof(data.command));
p= config.lookup(&data.uid);
if(p!=0){
bpf_probe_read_kernel(&data.message,sizeof(data.message), p->message);
}
else{
bpf_probe_read_kernel(&data.message,sizeof(data.message), message);
}
output.perf_submit(ctx,&data,sizeof(data));
return 0;
}
"""
b=BPF(text=program)
syscall=b.get_syscall_fnname("execve")
b.attach_kprobe(event=syscall,fn_name='hello_my_world')



b["config"][ct.c_int(0)] = ct.create_string_buffer(b"Hey root!")
b["config"][ct.c_int(1000)] = ct.create_string_buffer(b"Hi user 501!")
 
def print_event(cpu, data, size):  
   data = b["output"].event(data)
   print(f"{data.pid} {data.uid} {data.command.decode()} {data.message.decode()}")
 
b["output"].open_perf_buffer(print_event) 
while True:   
   b.perf_buffer_poll()








