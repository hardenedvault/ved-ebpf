## VED-eBPF: Kernel Exploit and Rootkit Detection using eBPF

VED ([Vault Exploit Defense](https://hardenedvault.net/blog/2023-07-09-protecting-linux-kernel-why-how/))-eBPF leverages eBPF (extended Berkeley Packet Filter) to implement runtime kernel security monitoring and exploit detection for Linux systems.

## Introduction

eBPF is an in-kernel virtual machine that allows code execution in the kernel without modifying the kernel source itself. eBPF programs can be attached to tracepoints, kprobes, and other kernel events to efficiently analyze execution and collect data.

VED-eBPF uses eBPF to trace security-sensitive kernel behaviors and detect anomalies that could indicate an exploit or rootkit. It provides two main detections:

* wCFI (Control Flow Integrity) traces the kernel call stack to detect control flow hijacking attacks. It works by generating a bitmap of valid call sites and validating each return address matches a known callsite.

* PSD (Privilege Escalation Detection) traces changes to credential structures in the kernel to detect unauthorized privilege escalations.

## How it Works

VED-eBPF attaches eBPF programs to kernel functions to trace execution flows and extract security events. The eBPF programs submit these events via perf buffers to userspace for analysis.

## wCFI

wCFI traces the call stack by attaching to functions specified on the command line. On each call, it dumps the stack, assigns a stack ID, and validates the return addresses against a precomputed bitmap of valid call sites generated from objdump and /proc/kallsyms.

If an invalid return address is detected, indicating a corrupted stack, it generates a wcfi_stack_event containing:

    * Stack trace
    * Stack ID
    * Invalid return address

This security event is submitted via perf buffers to userspace.

The wCFI eBPF program also tracks changes to the stack pointer and kernel text region to keep validation up-to-date.

## PSD

PSD traces credential structure modifications by attaching to functions like commit_creds and prepare_kernel_cred. On each call, it extracts information like:

    * Current process credentials
    * Hashes of credentials and user namespace
    * Call stack

It compares credentials before and after the call to detect unauthorized changes. If an illegal privilege escalation is detected, it generates a psd_event containing the credential fields and submits it via perf buffers.

## Prerequsites

VED-eBPF requires:

* Linux kernel v5.17+ (tested on v5.17)
* eBPF support enabled
* [BCC toolkit](https://github.com/iovisor/bcc)

## Current Status

VED-eBPF is currently a proof-of-concept demonstrating the potential for eBPF-based kernel exploit and rootkit detection. Ongoing work includes:

* Expanding attack coverage
* Performance optimization
* Additional kernel versions
* Integration with security analytics

## Conclusion

VED-eBPF shows the promise of eBPF for building efficient, low-overhead kernel security monitoring without kernel modification. By leveraging eBPF tracing and perf buffers, critical security events can be extracted in real-time and analyzed to identify emerging kernel threats for cloud native envionrment.
