// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "asmdefs.h"
#include "asmcommon.inc"

.globl oe_eaccept
.type oe_eaccept, @function
oe_eaccept:
.cfi_startproc

    push %rbx
    push %rcx
    movq %rdi, %rbx
    movq %rsi, %rcx

    // Execute EACCEPT.
    movq $ENCLU_EACCEPT, %rax
    ENCLU

    pop %rcx
    pop %rbx

    ret
.cfi_endproc

.globl oe_eacceptcopy
.type oe_eacceptcopy, @function
oe_eacceptcopy:
.cfi_startproc
    push %rbx
    push %rcx
    movq %rdi, %rbx
    movq %rsi, %rcx

    // Execute EACCEPTCOPY
    movq $ENCLU_EACCEPTCOPY, %rax
    ENCLU

    pop %rcx
    pop %rbx

    ret
.cfi_endproc

.globl oe_emodpe
.type oe_emodpe, @function
oe_emodpe:
.cfi_startproc
    push %rbx
    push %rcx
    movq %rdi, %rbx
    movq %rsi, %rcx

    // Execute EMODPE
    movq $ENCLU_EMODPE, %rax
    ENCLU

    pop %rcx
    pop %rbx

    ret
.cfi_endproc
