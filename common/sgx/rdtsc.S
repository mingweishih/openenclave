// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

.text
.globl  oe_rdtsc
.type oe_rdtsc, @function

oe_rdtsc:
.cfi_startproc
    lfence
    rdtsc
    shlq $0x20, %rdx
    orq %rdx, %rax
    lfence
    retq
.cfi_endproc
