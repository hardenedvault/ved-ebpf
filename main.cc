// Copyright (C) 2021-2023, HardenedVault Limited (https://hardenedvault.net)

#include <fstream>
#include <iostream>
#include <iomanip>
#include <string>
#include <cstdint>

#include "bcc_version.h"
#include "bcc_syms.h"
#include "BPF.h"

#include "main.h"
#include "exploit_detect/exploit_detect.h"

BPFExploitDetect bpf_ed;

void handle_output(void *cb_cookie, void *data, int data_size) {
    auto info = static_cast<wcfi_event_t *>(data);
    auto addrs = bpf_ed.bpf_wcfi_get_stack_addr(info->kernel_stack);
    bool log = true;

    if (data_size <= 0) {
        std::cout << "invaild perf event" << std::endl;
        log = true;
    }

    if (!addrs.size())
        std::cout << "stack may lost" << std::endl;

    bpf_ed.bpf_wcfi_ksyms_refresh();

    std::cout << "[" << info->time << "]: " << std::endl;
    std::cout << "PID:" << info->pid << " (" << info->name << ") " << std::endl;
    std::cout << "Hook function: " << bpf_ed.bpf_wcfi_ksyms_resolve(info->ip)
              << " (" << std::hex << info->ip << std::dec << ")" << std::endl;
    std::cout << "Stack pointer: " << std::hex << info->reg_sp << " - "
              << info->current_sp << std::dec << std::endl;
    std::cout << "Stack dump(" << info->kernel_stack << "):" << std::endl;

    for (auto addr : addrs) {
        std::cout << "    0x" << std::hex << addr << std::dec << " "
                  << bpf_ed.bpf_wcfi_ksyms_resolve(addr) << std::endl;
    }
    std::cout << std::endl;

    return;
}


int main(int argc, char** argv)
{
    unsigned long start, end;

    if (!bpf_ed.bpf_program_init(BPF_WCFI_PROGRAM)) {
        std::cerr << "init bpf program failed" << std::endl;
        exit(1);
    }

    if (!bpf_ed.bpf_wcfi_hooks_init(argc, argv, "wcfi_dump_kstack")) {
        std::cerr << "init bpf wcfi hooks failed" << std::endl;
        exit(1);
    }

    bpf_ed.bpf_wcfi_stack_init("kstack_table");
    if (!bpf_ed.bpf_wcfi_ksyms_init()) {
        std::cerr << "init bpf wcfi ksyms failed" << std::endl;
        exit(1);
    }

    bpf_ed.bpf_wcfi_text(&start, &end);

    std::vector<unsigned long> callsites = read_objdump("/usr/lib/debug/boot/vmlinux-5.17.0-1-amd64", start, &end, true);
    if (callsites.size() <= 0) {
        std::cerr << "failed init callsite" << std::endl;
        exit(1);
    }

    // refer to mian.h BPF_WCFI_PROGRAM
    unsigned long init_stack = read_kallsyms("init_stack");
    bpf_ed.bpf_wcfi_callsite_bitmap_init(start, end, init_stack);

    for(unsigned long addr : callsites) {
        bpf_ed.bpf_wcfi_callsite_bitmap_update(addr, WCFI_CALLSITE_FLAG);
    }

    for (auto addr : bpf_ed.bpf_wcfi_ksyms_list_address(asm_functions)) {
        bpf_ed.bpf_wcfi_callsite_bitmap_update(addr, WCFI_CALLSITE_FLAG);
    }

    for (auto addr : bpf_ed.bpf_wcfi_ksyms_list_address(exc_asm_functions)) {
        bpf_ed.bpf_wcfi_callsite_bitmap_update(addr, WCFI_EXCASM_FLAG);
    }

    if (bpf_ed.bpf_wcfi_perf_buffer_init("wcfi_events", &handle_output)) {
        while(true) {
            bpf_ed.bpf_wcfi_perf_poll();
        }
    }

    return 0;
}
