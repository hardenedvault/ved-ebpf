// Copyright (C) 2021-2023, HardenedVault Limited (https://hardenedvault.net)

#include "main.h"
#include "event.h"

void handle_event(BPFExploitDetect bpf_ed, void *cb_cookie, void *data, int data_size) {
    event be = (event)data;
}

std::string event::basic_info_string() {
    std::string ret;


    std::cout << "[" << time << "]: " << std::endl;
    std::cout << "PID:" << pid << " (" << name << ") " << std::endl;
    std::cout << "Hook function: "
              << std::hex << ip << std::dec << std::endl;
    std::cout << "Stack pointer: 0x" << std::hex << info->reg_sp << " < "
              << info->current_sp << " + 4096" << std::dec << std::endl;
    std::cout << "Stack dump(" << info->kernel_stack << "):" << std::endl;

    for (auto addr : addrs) {
        std::cout << "    0x" << std::hex << addr << std::dec << " "
                  << bpf_ed.bpf_wcfi_ksyms_resolve(addr) << std::endl;
    }
    std::cout << std::endl;
}

std::string wcfi_stack_event::info_string(BPFExploitDetect bpf_ed) {
    //std::string ret = "";
    std::vector<unsigned long> addrs = bpf_ed.bpf_wcfi_get_stack_addr(kstack_id);

    if (!addr.size())
        std::cerr << "call stack may miss: " << kstack_id << std::endl;

    bpf_ed.bpf_wcfi_ksyms_refresh();

    basic_info_string();

    for (auto addr : addrs) {
        std::cout << "0x" << std::hex << addr << std::dec << " "
                  << bpf_ed.bpf_wcfi_ksyms_resolve(addr) << std::endl;
    }
    std::cout << std::endl;

    return "";
}

        std::string wcfi_stack_event::info_string(BPFExploitDetect bpf_ed)
