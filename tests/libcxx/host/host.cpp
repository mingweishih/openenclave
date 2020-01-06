// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/tests.h>
#include <inttypes.h>
#include <cassert>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <thread>
#include <vector>
#include "libcxx_u.h"
#include "threadArgs.h"

// Host maintains a map of enclave key to host thread ID
static std::map<uint64_t, int> _enclave_host_id_map;
// Since C++ thread does not allow for using the built-in
// thread id in thread operations such as thread referencing
// and joining, we use customized host_thread_id to keep track
// of created thread objects
static std::vector<std::thread> _host_thread_list;
static std::map<std::thread::id, int> _thread_host_id_map;

static atomic_flag_lock _host_lock;

void test(oe_enclave_t* enclave)
{
    int ret = 1;
    char test_name[STRLEN];
    oe_result_t result = enc_test(enclave, &ret, test_name);
    OE_TEST(result == OE_OK);

    if (ret == 0)
    {
        printf("PASSED: %s\n", test_name);
    }
    else
    {
        printf("FAILED: %s (ret=%d)\n", test_name, ret);
        abort();
    }
}

void host_exit(int arg)
{
    exit(arg);
}

struct thread_args_t
{
    oe_enclave_t* enclave;
    uint64_t enc_key;
};

void* host_enclave_thread(void* args)
{
    thread_args_t* thread_args = reinterpret_cast<thread_args_t*>(args);
    // need to cache the values for enc_key and enclave now before _host_lock
    // is unlocked after assigning the host_thread_id to the _enclave_host_id_map
    // because args is a local variable in the calling method which may exit at
    // any time after _host_lock is unlocked which may cause a segfault
    uint64_t enc_key = thread_args->enc_key;
    oe_enclave_t* enclave = thread_args->enclave;
    int host_thread_id = 0;

    {
        // Using atomic_thread_host_id_map lock to ensure the mapping is updated before
        // the host_thread_id lookup
        atomic_lock lock(_host_lock);

        std::thread::id thread_id = std::this_thread::get_id();
        OE_TEST(_thread_host_id_map.find(thread_id) != _thread_host_id_map.end());
        // Lookup the host_thread_id from the thread::id
        host_thread_id = _thread_host_id_map[thread_id];

        // Populate the enclave_host_id map with the host_thread_id
        _enclave_host_id_map[enc_key] = host_thread_id;
    }

    OE_TEST(host_thread_id != 0);
    printf(
        "host_enclave_thread(): enc_key=%" PRIu64 " has host thread_id of %#10x\n",
        enc_key,
        host_thread_id);

    // Launch the thread
    oe_result_t result = enc_enclave_thread(enclave, enc_key);
    OE_TEST(result == OE_OK);

    return NULL;
}

void host_create_thread(uint64_t enc_key, oe_enclave_t* enclave)
{
    thread_args_t thread_args = {enclave, enc_key};
    int host_thread_id = 0;

    {
        // Using atomic locks to protect the enclave_host_id_map
        // and update the host_thread_id mapping upon a thread creation
        atomic_lock lock(_host_lock);
        _enclave_host_id_map.insert(std::make_pair(enc_key, host_thread_id));

        // New Thread is created and executes host_enclave_thread
        _host_thread_list.push_back(
            std::thread(host_enclave_thread, &thread_args));

        std::thread::id thread_id = _host_thread_list.back().get_id();
        host_thread_id = _host_thread_list.size();
        _thread_host_id_map[thread_id] = host_thread_id;
    }

    // Main host thread waits for the enclave id to host id mapping to be
    // updated
    int mapped_thread_id = 0;
    while (0 == mapped_thread_id)
    {
        {
            atomic_lock lock(_host_lock);
            mapped_thread_id = _enclave_host_id_map[enc_key];
        }
        if (0 == mapped_thread_id)
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    }

    // Sanity check
    if (host_thread_id != mapped_thread_id)
    {
        printf("Host thread id incorrect in the enclave_host_id_map\n");
        abort();
    }
}

int host_join_thread(uint64_t enc_key)
{
    int ret_val = 0;
    int host_thread_id = 0;

    // Find the host_thread_id from the enclave_host_id_map using the enc_key
    {
        // Using atomic locks to protect the enclave_host_id_map
        atomic_lock lock(_host_lock);
        std::map<uint64_t, int>::iterator it =
            _enclave_host_id_map.find(enc_key);
        if (it != _enclave_host_id_map.end())
        {
            host_thread_id = it->second;
            lock.unlock();

            auto &t = _host_thread_list[host_thread_id - 1];
            OE_TEST(t.joinable());
            t.join();

            // Update the shared memory only after join
            {
                // Delete the enclave_host_id mapping as host thread_id may be reused
                // in future
                lock.lock();
                _enclave_host_id_map.erase(enc_key);

                printf(
                    "host_join_thread() succeeded for enclave id=%" PRIu64 ", host "
                    "id=%#10x\n",
                    enc_key,
                    host_thread_id);
            }
        }
        else
        {
            printf(
                "host_join_thread() failed to find enclave id=%" PRIu64 " in host "
                "map\n",
                enc_key);
            abort();
        }
    }

    return ret_val;
}

int host_detach_thread(uint64_t enc_key)
{
    printf("host_detach_thread():enclave key=%" PRIu64 "\n", enc_key);

    // Find the host_thread_id from the enclave_host_id_map using the enc_key

    // Using atomic locks to protect the enclave_host_id_map
    atomic_lock lock(_host_lock);
    std::map<uint64_t, int>::iterator it =
        _enclave_host_id_map.find(enc_key);
    if (it != _enclave_host_id_map.end())
    {
        int host_thread_id = it->second;
        lock.unlock();

        auto &t = _host_thread_list[host_thread_id - 1];
        t.detach();

        {
            // Delete the _enclave_host_id mapping as the host thread_id may be
            // reused in future
            lock.lock();
            _enclave_host_id_map.erase(enc_key);
        }
        printf(
            "host_detach_thread() enclave id=%" PRIu64 ", host "
            "thread id=%#10x\n",
            enc_key,
            host_thread_id);
    }
    else
    {
        printf(
            "host_detach_thread() failed to find enclave key=%" PRIu64 " in host "
            "map\n",
            enc_key);
        abort();
    }
    return 0;
}

static int _get_opt(
    int& argc,
    const char* argv[],
    const char* name,
    const char** arg = NULL)
{
    for (int i = 0; i < argc; i++)
    {
        if (strcmp(argv[i], name) == 0)
        {
            if (!arg)
            {
                memmove(
                    (void*)&argv[i],
                    &argv[i + 1],
                    static_cast<size_t>(argc - i) * sizeof(char*));
                argc--;
                return 1;
            }

            if (i + 1 == argc)
            {
                return -1;
            }

            *arg = argv[i + 1];
            memmove(
                (char**)&argv[i],
                &argv[i + 2],
                static_cast<size_t>(argc - i - 1) * sizeof(char*));
            argc -= 2;
            return 1;
        }
    }

    return 0;
}

int main(int argc, const char* argv[])
{
    oe_result_t result;
    oe_enclave_t* enclave = NULL;
    uint32_t flags = OE_ENCLAVE_FLAG_DEBUG;

    // Check for the --sim option:
    if (_get_opt(argc, argv, "--simulate") == 1)
    {
        flags |= OE_ENCLAVE_FLAG_SIMULATE;
    }
    else
    {
        flags = oe_get_create_flags();
    }

    // Check argument count:
    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE\n", argv[0]);
        exit(1);
    }

    // Disable stdout buffering on host
    setbuf(stdout, NULL);

    printf("=== %s: %s\n", argv[0], argv[1]);

    // Create the enclave:
    if ((result = oe_create_libcxx_enclave(
             argv[1], OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclave)) != OE_OK)
    {
        oe_put_err("oe_create_enclave(): result=%u", result);
    }

    // Invoke "enc_test()" in the enclave.
    test(enclave);

    // Shutdown the enclave.
    if ((result = oe_terminate_enclave(enclave)) != OE_OK)
    {
        oe_put_err("oe_terminate_enclave(): result=%u", result);
    }

    printf("\n");

    return 0;
}
