// +build ignore

#include "common.h"
#include "bpf_tracing.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct event{
    u32 pid;
    u32 uid;
    u8 command[256];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events SEC(".maps");

// Force emitting struct event into the ELF.
const struct event *unused __attribute__((unused));

SEC("uretprobe/bash_readline")
int uretprobe_bash_readline(struct pt_regs *ctx){
    struct event event;

    event.pid = bpf_get_current_pid_tgid();

    event.uid = bpf_get_current_uid_gid();

    bpf_probe_read(&event.command, sizeof(event.command), (void *) PT_REGS_RC(ctx));

    bpf_perf_event_output(ctx, &events,BPF_F_CURRENT_CPU, &event, sizeof(event));
    return 0;
}