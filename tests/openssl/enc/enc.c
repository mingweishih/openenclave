// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/edger8r/enclave.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/crypto/init.h>
#include <sys/mount.h>
#include "openssl_t.h"
#include "tu_local.h" /* Header from openssl/test/testutil */

extern char** __environ;

extern int main(int argc, char* argv[]);

int enc_test(int argc, char** argv, char** env)
{
    int ret = 1;
    const BIO_METHOD* tap = NULL;

    /* Directly use environ from host. */
    __environ = env;

    /* Initialize socket and host fs. */
    if (oe_load_module_host_socket_interface() != OE_OK)
        goto done;

    if (oe_load_module_host_resolver() != OE_OK)
        goto done;

#ifndef CODE_COVERAGE
    /*
     * When enabling code coverage analysis, libgcov should initialize the host
     * fs already so we do not do it again here. Otherwise, the
     * oe_load_module_host_file_system will fail.
     */
    if (oe_load_module_host_file_system() != OE_OK)
        goto done;

    if (mount("/", "/", OE_HOST_FILE_SYSTEM, 0, NULL))
        goto done;
#endif

    if (oe_is_symcrypt_engine_available() == 1)
        printf("symcrypt engine is available\n");
    else
        printf("symcrypt engine is not available\n");

    /*
     * Hold the reference to the tap method that is used by the OpenSSL test
     * framework such that we can free it (which the framework does not do
     * that). Without doing this, DEBUG_MALLOC will report memory leaks.
     */
    tap = BIO_f_tap();

    /* Perform the test. */
    ret = main(argc, argv);

done:
#ifndef CODE_COVERAGE // Avoid conflicts with libgcov.
    umount("/");
#endif
    if (__environ)
        __environ = NULL;
    if (tap)
        BIO_meth_free((BIO_METHOD*)tap);

    return ret;
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* AllowDebug */
    6144, /* HeapPageCount */
    128,  /* StackPageCount */
    1);   /* TCSCount */
