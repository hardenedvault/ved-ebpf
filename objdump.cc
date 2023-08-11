// Copyright (C) 2021-2023, HardenedVault Limited (https://hardenedvault.net)

#include <fstream>
#include <iostream>
#include <iomanip>
#include <string>
#include <stdio.h>
#include <string.h>

#include "bcc_version.h"
#include "bcc_syms.h"
#include "BPF.h"


std::vector<unsigned long> read_objdump(char *objfile, unsigned long start, unsigned long *end, bool kcore)
{
    std::vector<unsigned long> ret_addrs;
    char cmd[0x100] = "0", *raw_line = NULL;
    bool push_next_addr = false;
    size_t len = 0;
    FILE *objdump;

    sprintf(cmd, "objdump --no-show-raw-insn -d %s", objfile);
    objdump = popen(cmd, "r");
    if (!objdump) {
        perror(cmd);
        exit(1);
    }

    while(getline(&raw_line, &len, objdump) != -1) {
        unsigned long addr;
        char inst1[0x10], inst2[0x10];

        if (push_next_addr && sscanf(raw_line, "%lx:", &addr)) {
            if (*end < addr - 0xffffffff81000000 + start)
                *end = addr - 0xffffffff81000000 + start;
            if (sscanf(raw_line, "%lx:\t%s\n", &addr, inst1)
                    && std::string(inst1).find("nop", 0) != std::string::npos){
                ret_addrs.push_back(addr - 0xffffffff81000000 + start);
                push_next_addr = true;
            } else {
                ret_addrs.push_back(addr - 0xffffffff81000000 + start);
                push_next_addr = false;
            }
        }

        if (sscanf(raw_line, "%lx:\t%s\n", &addr, inst1)) {
            if (!strncmp(inst1, "call", 5)){
                unsigned long real_addr = addr - 0xffffffff81000000 + start;

                if (real_addr > start)
                    push_next_addr = true;
                else
                    std::cerr << "out of address space: 0x"
                              << std::hex << real_addr << std::dec << std::endl;
            } else if (sscanf(raw_line, "%lx:\t%s %s\n", &addr, inst1, inst2)) {
                if (std::string(inst1).find("cs", 0) != std::string::npos
                 && std::string(inst2).find("call", 0) != std::string::npos) {
                    unsigned long real_addr = addr - 0xffffffff81000000 + start;
                    if (real_addr > start)
                        push_next_addr = true;
                    else
                        std::cerr << "out of address space: 0x"
                                  << std::hex << real_addr << std::dec << std::endl;
                }
            }
        }
    }

    return ret_addrs;
}

unsigned long read_kallsyms(std::string obj_sym)
{
    FILE *kallsyms_file;
    char *raw_line = NULL;
    size_t len = 0;

    kallsyms_file = fopen("/proc/kallsyms", "r");
    if (!kallsyms_file) {
        perror("open /proc/kallsyms failed");
        exit(1);
    }

    while(getline(&raw_line, &len, kallsyms_file) != -1) {
        unsigned long addr;
        char sym_type, sym[0x40] = "\0", mod[0x40] = "\0";

        if (sscanf(raw_line, "%lx %c %s %s\n", &addr, &sym_type, sym, mod) < 3) {
            printf("failed read line: %s\n", raw_line);
            exit(1);
        }

        if (std::string(sym) == obj_sym)
            return addr;
    }

    return 0;
}
