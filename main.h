// Copyright (C) 2021-2023, HardenedVault Limited (https://hardenedvault.net)

#include <string>
#include <stdbool.h>

std::vector<unsigned long> read_objdump(char *objfile, unsigned long start, unsigned long *end, bool kcore);
unsigned long read_kallsyms(std::string obj_sym);

std::map<std::string, bool> asm_functions = {
    {"secondary_startup_64_no_verify", true},
};

std::map<std::string, bool> exc_asm_functions = {
    {"asm_exc_divide_error", true},
    {"asm_exc_divide_error", true},
    {"asm_exc_overflow", true},
    {"asm_exc_bounds", true},
    {"asm_exc_device_not_available", true},
    {"asm_exc_coproc_segment_overrun", true},
    {"asm_exc_spurious_interrupt_bug", true},
    {"asm_exc_coprocessor_error", true},
    {"asm_exc_simd_coprocessor_error", true},
    {"asm_exc_invalid_tss", true},
    {"asm_exc_segment_not_present", true},
    {"asm_exc_stack_segment", true},
    {"asm_exc_general_protection", true},
    {"asm_exc_alignment_check", true},
    {"asm_exc_invalid_op", true},
    {"asm_exc_int3", true},
    {"asm_exc_page_fault", true},
    {"asm_exc_machine_check", true},
    {"asm_exc_nmi_noist", true},
    {"asm_exc_debug", true},
    {"asm_exc_double_fault", true},
    {"asm_exc_vmm_communication", true},
    {"asm_exc_xen_hypervisor_callback", true},
    {"asm_exc_xen_unknown_trap", true},
    {"asm_exc_nmi", true},
    {"asm_common_interrupt", true},
    {"asm_sysvec_error_interrupt", true},
    {"asm_sysvec_spurious_apic_interrupt", true},
    {"asm_sysvec_apic_timer_interrupt", true},
    {"asm_sysvec_x86_platform_ipi", true},
    {"asm_sysvec_reschedule_ipi", true},
    {"asm_sysvec_irq_move_cleanup", true},
    {"asm_sysvec_reboot", true},
    {"asm_sysvec_call_function_single", true},
    {"asm_sysvec_call_function", true},
    {"asm_sysvec_threshold", true},
    {"asm_sysvec_deferred_error", true},
    {"asm_sysvec_thermal", true},
    {"asm_sysvec_irq_work", true},
    {"asm_sysvec_kvm_posted_intr_ipi", true},
    {"asm_sysvec_kvm_posted_intr_wakeup_ipi", true},
    {"asm_sysvec_kvm_posted_intr_nested_ipi", true},
    {"asm_sysvec_hyperv_callback", true},
    {"asm_sysvec_hyperv_reenlightenment", true},
    {"asm_sysvec_hyperv_stimer0", true},
    {"asm_sysvec_xen_hvm_callback", true},
    {"asm_sysvec_kvm_asyncpf_interrupt", true},
};

const std::string BPF_WCFI_PROGRAM = R"(
#include <linux/kernel.h>
#include <linux/ptrace.h>
#include <linux/sched.h>

#define WCFI_CALLSITE_FLAG 0x1
#define WCFI_EXCASM_FLAG 0x2

struct wcfi_event_t {
    int pid;
#define WCFI_TASK_COMM_LEN 0x20
    char name[WCFI_TASK_COMM_LEN];
    int kernel_stack;
    unsigned long reg_sp;
    unsigned long current_sp;
    unsigned long ip;
    unsigned long time;
};

BPF_HASH(wcfi_callsite_bitmap, unsigned, uint8_t, 0x4000000);
BPF_HASH(wcfi_callsite_bitmap_maxmin, unsigned, unsigned, 2);
BPF_HASH(wcfi_init_stack, int, unsigned long, 1);
BPF_PERF_OUTPUT(wcfi_events);
BPF_STACK_TRACE(kstack_table, 0x1000);

int wcfi_dump_kstack(struct pt_regs *ctx) {
    struct task_struct *cu = (struct task_struct *)bpf_get_current_task();
    unsigned long addrs[0x30];
    unsigned long stack_mask = ~((unsigned long)(1 << 16) - 1);

    bpf_get_stack(ctx, addrs, 0x30*8, 0);

    if (((unsigned long)ctx->sp & stack_mask)
        != ((unsigned long)cu->stack & stack_mask)) {
        int init_stack_idx = 0;
        unsigned long *init_stack = wcfi_init_stack.lookup(&init_stack_idx);
        // PID:0 (swapper/0)
        if (init_stack && cu->stack != *init_stack && cu->pid != 0) {
            struct wcfi_event_t event = {};
            struct task_struct *cu = (struct task_struct *)bpf_get_current_task();
            event.pid = bpf_get_current_pid_tgid() >> 32;
            bpf_get_current_comm(&event.name, sizeof(event.name));
            event.kernel_stack = kstack_table.get_stackid(ctx, BPF_F_REUSE_STACKID);
            event.reg_sp = ctx->sp;
            event.current_sp = (unsigned long)cu->stack;
            event.time = bpf_ktime_get_ns();
            event.ip = cu->thread.sp;
            wcfi_events.perf_submit(ctx, &event, sizeof(struct wcfi_event_t));
            return 0;
        } // failed 
    }

    for(int i = 1; i < 0x30; i++) {
        unsigned idx = addrs[i] & 0xffffffff;
        uint8_t *val;

        val = wcfi_callsite_bitmap.lookup(&idx);
        if (idx == 0)
            break;
        // right callsite
        if (val) {
            if (*val == WCFI_CALLSITE_FLAG)
                continue;
            // exc asm may jump to/from somewhere without callsite
            if (*val == WCFI_EXCASM_FLAG) {
                i++;
                continue;
            }
        }
        if(!val) {
            unsigned max_idx = 0xffff, min_idx = 0x0;
            unsigned *max = wcfi_callsite_bitmap_maxmin.lookup(&max_idx);
            unsigned *min = wcfi_callsite_bitmap_maxmin.lookup(&min_idx);
            if (min && max && (idx > *max || idx < *min))
                continue;
        }if (idx != 0 && !val) {
            struct wcfi_event_t event = {};
            struct task_struct *cu = (struct task_struct *)bpf_get_current_task();
            event.pid = bpf_get_current_pid_tgid() >> 32;
            bpf_get_current_comm(&event.name, sizeof(event.name));
            event.kernel_stack = kstack_table.get_stackid(ctx, BPF_F_REUSE_STACKID);
            event.reg_sp = ctx->sp;
            event.current_sp = (unsigned long)cu->stack;
            event.time = bpf_ktime_get_ns();
            event.ip = addrs[i];
            wcfi_events.perf_submit(ctx, &event, sizeof(struct wcfi_event_t));
            break;
        }
    }

    return 0;
}

)";




const std::string BPF_PSD_PROGRAM = R"(
#include <linux/kernel.h>
#include <linux/ptrace.h>

struct psd_event_t {
    int pid;
#define WCFI_TASK_COMM_LEN 0x20
    char name[WCFI_TASK_COMM_LEN];
    unsigned long ip;
    unsigned long time;
    unsigned long cred_p; // current->cred
    unsigned long cred_hash;
    unsigned long user_namespace_hash;
};


BPF_PERF_OUTPUT(psd_events);

int psd_dump_cred(struct pt_regs *ctx) {
    struct psd_event_t event = {};
    struct task_struct *cu = (struct task_struct *)bpf_get_current_task();

    event.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&event.name, sizeof(event.name));
    event.ip = ctx->ip;
    event.time = bpf_ktime_get_ns();

    int rc = kstack_key.perf_submit(ctx, &event, sizeof(struct psd_event_t));
    if (rc < 0)
        bpf_trace_printk("perf_output failed: %d\\n", rc);

    return 0;
}

)";
