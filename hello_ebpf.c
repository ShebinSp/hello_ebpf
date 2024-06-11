#include "/home/katana/c/headers/vmlinux.h"
#include <bpf/bpf_helpers.h>

struct event
{
    u32 pid;
    u8 comm[100];
};

struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096);
} events SEC(".maps");
/*
    Here we import the `vmlinux.h` header file, which contains the kernel's data structures and function prototypes. Then
    we inluce the  `bpf_helpers.h` header file, which contains helper functions for eBPF programs.
    Then we define a `struct` to hold the event data, and then we define a BPF map to store the events. We will use this
    map to communitcate the events between the eBPF program, which will run in kernel space, and the user space program.
*/

// Defining the hooks that it will be attached to:
SEC("kprobe/sys_execve")

int hello_execve(struct pt_regs *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    pid_t pid = id >> 32;
    pid_t tid = (u32)id;

    if (pid != tid)
        return 0;
    
    struct event *e;
    
    e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);

    if (!e)
        return 0;
    

    e->pid = pid;
    bpf_get_current_comm(&e->comm, 100);
    bpf_ringbuf_submit(e, 0);
    return 0;
}
char _license[] SEC("license") = "GPL";

/*
Here we define a function, `hello_execbe`, and attached to the `sys_execve` system call using the `kprobe` hook. `kprobe`
is one of many hooks that eBPF provides, and it's used to trace kernel functions. This hook will trigger our `hello_execve`
function right before the `sys_execve` system call is executed.
    Inside the `hello_execve` function, we first get the process ID and the thread ID, and then we check if they are the
same.If they are not same, that means we are in a thread, and we don't want to treace threads, so we exit the eBPF progrm by 
returning zero.
    We then reserve space in the `events` map to store the event data, and then we fill the event data with the process ID
and the command name of the process. Then we submit the event to the `events` map.
*/
