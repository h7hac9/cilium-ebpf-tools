// +build ignore

#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAXARGLEN 15

char __license[] SEC("license") = "Dual MIT/GPL";

struct event {
    u64 cgroup_id;
    u32 pid;
    u32 ppid;
    u32 namespace_pid;
    u32 namespace_ppid;
    u32 uid;
    u32 gid;
    u32 ns_pid_id;
    u8 filename[256];
    u8 argvs[16][512];
    u32 argv_len;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries,  16 * 1024);
} events SEC(".maps");

// Force emitting struct event into the ELF.
const struct event *unused __attribute__((unused));

SEC("tracepoint/syscalls/sys_enter_execve")
int sys_enter_execve(struct trace_event_raw_sys_enter *ctx) {
    struct event *event;
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }

    event->cgroup_id = bpf_get_current_cgroup_id();

    char *filename_ptr = (char *)BPF_CORE_READ(ctx, args[0]);
    bpf_probe_read_str(&event->filename, sizeof(event->filename), filename_ptr);

    char * const *argv_ptr = (char * const *) BPF_CORE_READ(ctx, args[1]);

    event->argv_len = 0;
    bool flag = false;

    for (int i = 0; i < MAXARGLEN; i++){
        char *argv;
        bpf_probe_read(&argv, sizeof(argv), &argv_ptr[i]);

        if (!argv) {
            flag = true;
            break;
        }

        event->argv_len += 1;
        bpf_probe_read_str(&event->argvs[i], sizeof(event->argvs[i]), argv);
    }

    if (!flag){
        event->argv_len += 1;
        char ellipsis[] = "...";
        bpf_probe_read_user_str(&event->argvs[MAXARGLEN], sizeof(event->argvs[MAXARGLEN]), (void *)ellipsis);
    }

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent_task = BPF_CORE_READ(task, real_parent);

    // host pid & ppid
    event->pid = BPF_CORE_READ(task, tgid);
    event->ppid = BPF_CORE_READ(parent_task, tgid);

    // namespace pid
    struct nsproxy *namespaceproxy = BPF_CORE_READ(task, nsproxy);
    struct pid_namespace *pid_ns_children = BPF_CORE_READ(namespaceproxy, pid_ns_for_children);
    unsigned int level = BPF_CORE_READ(pid_ns_children, level);

    event->namespace_pid = BPF_CORE_READ(task, group_leader, thread_pid, numbers[level].nr);

    // namespace ppid
    struct nsproxy *parent_namespaceproxy = BPF_CORE_READ(parent_task, nsproxy);
    struct pid_namespace *parent_pid_ns_children = BPF_CORE_READ(parent_namespaceproxy, pid_ns_for_children);
    unsigned int parent_level = BPF_CORE_READ(parent_pid_ns_children, level);

    event->namespace_ppid = BPF_CORE_READ(parent_task,group_leader, thread_pid, numbers[parent_level].nr);

    // pid namespace id
    event->ns_pid_id = BPF_CORE_READ(namespaceproxy, pid_ns_for_children, ns.inum);

    bpf_ringbuf_submit(event, 0);

    return 0;
}