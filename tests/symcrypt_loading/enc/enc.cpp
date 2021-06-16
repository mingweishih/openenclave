// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "symcrypt_loading_t.h"

#include "symcrypt.h"

static uint64_t oe_getbv()
{
    uint32_t eax, edx, index;
    eax = edx = 0;
    index = 0; // XCR0 register is returned

    // Ensure that Processor and OS support extended states feature. XGETBV will
    // #GP fault otherwise.
    /* Invoke xgetbv to get the value of the Extended Control Register XCR0
     */
    asm volatile(".byte 0x0f,0x01,0xd0" /* xgetbv */
                 : "=a"(eax), "=d"(edx)
                 : "c"(index));
    return eax + ((uint64_t)edx << 32);
}

static void SymCryptSelfTest()
{
    printf("SymCryptModuleInit ... ");
    SYMCRYPT_MODULE_INIT();
    printf("done\n");

    printf("SymCrypt3DesSelftest ... ");
    SymCrypt3DesSelftest();
    printf("done\n");

    printf("SymCryptAesSelftest ... ");
    SymCryptAesSelftest(SYMCRYPT_AES_SELFTEST_ALL);
    printf("done\n");

    printf("SymCryptAesSelftest ... ");
    SymCryptAesCmacSelftest();
    printf("done\n");

    printf("SymCryptAesSelftest ... ");
    SymCryptCcmSelftest();
    printf("done\n");

    printf("SymCryptGcmSelftest ... ");
    SymCryptGcmSelftest();
    printf("done\n");

    printf("SymCryptXtsAesSelftest ... ");
    SymCryptXtsAesSelftest();
    printf("done\n");

    printf("SymCryptXtsAesSelftest ... ");
    SymCryptRngAesInstantiateSelftest();
    printf("done\n");

    printf("SymCryptRngAesReseedSelftest ... ");
    SymCryptRngAesReseedSelftest();
    printf("done\n");

    printf("SymCryptRngAesGenerateSelftest ... ");
    SymCryptRngAesGenerateSelftest();
    printf("done\n");

    printf("SymCryptHmacSha1Selftest ... ");
    SymCryptHmacSha1Selftest();
    printf("done\n");

    printf("SymCryptHmacSha256Selftest ... ");
    SymCryptHmacSha256Selftest();
    printf("done\n");

    printf("SymCryptHmacSha512Selftest ... ");
    SymCryptHmacSha512Selftest();
    printf("done\n");

    printf("SymCryptParallelSha256Selftest ... ");
    SymCryptParallelSha256Selftest();
    printf("done\n");

    printf("SymCryptParallelSha256Selftest ... ");
    SymCryptParallelSha512Selftest();
    printf("done\n");

    printf("SymCryptTlsPrf1_1SelfTest ... ");
    SymCryptTlsPrf1_1SelfTest();
    printf("done\n");

    printf("SymCryptTlsPrf1_1SelfTest ... ");
    SymCryptTlsPrf1_2SelfTest();
    printf("done\n");

    printf("SymCryptTlsPrf1_1SelfTest ... ");
    SymCryptHkdfSelfTest();
    printf("done\n");
}

int test_enclave()
{
    SymCryptSelfTest();

    uint64_t result = oe_getbv();
    if ((result & 0x6) == 0x6)
        printf("AVX2 is supported\n");
    else
        printf("AVX2 is not supported\n");

    return 0;
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* Debug */
    1024, /* NumHeapPages */
    1024, /* NumStackPages */
    1);   /* NumTCS */
