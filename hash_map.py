#!/usr/bin/python
from bcc import BPF
import time
import redis
# Create a connection to the local Redis server
r = redis.StrictRedis(host='localhost', port=6379, db=1)
program = """
BPF_HASH(my_table);
int hello(void *ctx){
    u64 counter = 0;
    u64 *p;
    u64 uid;
    uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    p = my_table.lookup(&uid);
    if (p != 0) {
        counter = *p;
    }
    counter++;
    my_table.update(&uid, &counter);
    return 0;
}
"""
b = BPF(text=program)
syscall = b.get_syscall_fnname("execve")
b.attach_kprobe(event=syscall, fn_name='hello')
while True:
    time.sleep(2)
    for k, v in b['my_table'].items():
        uid = k.value
        counter = v.value
        print(f"UID: {uid}        Counter: {counter}")
        r.set(uid,counter)


