;; Copyright (c) Open Enclave SDK contributors.
;; Licensed under the MIT License.
.CODE

PUBLIC oe_rdtsc
oe_rdtsc PROC

    lfence
    rdtsc
    shl rdx, 20h
    or rax, rdx
    lfence
    ret

oe_rdtsc ENDP

END
