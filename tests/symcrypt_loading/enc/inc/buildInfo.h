#include "symcrypt_version.inc"

#define _SYMCRYPT_JOIN(a, b) #a "." #b
#define _SYMCRYPT_EXPAND_JOIN(a, b) _SYMCRYPT_JOIN(a, b)
#define SYMCRYPT_BUILD_INFO_BRANCH "master"
#define SYMCRYPT_BUILD_INFO_COMMIT "2021-06-10T15:15:22+00:00_1956918"
#define SYMCRYPT_BUILD_INFO_VERSION                                  \
    _SYMCRYPT_EXPAND_JOIN(                                           \
        _SYMCRYPT_EXPAND_JOIN(                                       \
            SYMCRYPT_CODE_VERSION_API, SYMCRYPT_CODE_VERSION_MINOR), \
        SYMCRYPT_CODE_VERSION_PATCH)
#define SYMCRYPT_BUILD_INFO_TIMESTAMP "2021-06-11T17:13:58"
