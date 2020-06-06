Generalize the Calling Mechanisms of TEE Functions
=====

Introduction
------------

Unlike typical function invocations via `call` instructions, TEE functions require
specialized calling mechanisms that allow an enclave and a host to interact with each other.
In the Open Enclave SDK, we use OCALLs to refer to the host-side functions for the
enclave to use, and use ECALLs to refer to the enclave-side functions for the host to use.
The invocation of an OCALL/ECALL is analogous to message passing between two isolated entities via a channel.
Regardless of the type of a channel, which depends on the implementation of TEEs, invoking an ECALL/OCALL requires
a contract between the enclave and the host so that they know what messages to send and how to
interpret the messages they receive and to take actions accordingly.

This document describes the current implementation of ECALL/OCALL invocations, its limitations, and the
proposal of code refactoring.

Current Implementation
-----------------------

**EDL**

The Open Enclave SDK currently uses the oeedger8r tool to generate the stub code of ECALLs and OCALLs
from an EDL file. The following example shows an file that defines an ECALL `sample_ecall()`
and an OCALL `sample_ocall()`.

```
// sample.edl
enclave
{
    trusted
    {
        public void sample_ecall();
    };

    untrusted
    {
        public void sample_ocall();
    };
}
```

Given the `sample.edl`, the oeedger8r generates `sample_u.c`/`sample_u.h` as the host-side stub
and `sample_t.c`/`sample_t.h` as the enclave-side stub.

**ECALL Invocation**

To invoke an ECALL, the host simply calls the `sample_ecall()` function by feeding
the pointer of the target `enclave` struct as the following code snippet.

```
result = sample_ecall(enclave);
```

The `sample_ecall()`, which is defined in `sample_u.c`, performs a series of checks,
marshals the arguments, and invokes the `oe_call_enclave_function()` function
as the following example.

```
if ((_result = oe_call_enclave_function(
        enclave,
        sample_fcn_id_sample_ecall,
        _input_buffer,
        _input_buffer_size,
        _output_buffer,
        _output_buffer_size,
        &_output_bytes_written)) != OE_OK)
    goto done;
```

The function, which is part of the `oehost` library, eventually dispatches the
provided arguments to the target enclave (specified by the `enclave`). Clearly,
the argument `sample_fcn_id_sample_ecall` (with the `enum` type, defined in both
`sample_u.h` and `sample_t.h`) is used as an identifier that allows the enclave to
locate the corresponding ECALL. More specifically, `sample_t.c` defines
`__oe_ecalls_table` (an array of function pointers) and `__oe_ecalls_table_size` as follows.

```
oe_ecall_func_t __oe_ecalls_table[] = {
    (oe_ecall_func_t) ecall_sample_ecall
};

size_t __oe_ecalls_table_size = OE_COUNTOF(__oe_ecalls_table);
```

Both of them are global variables that are linked by the `oecore` library
and are used in the `oe_handle_call_enclave_function()` function,
which processes every request of ECALLs. The following code snippet shows
how the function looks up the ECALL wrapper from the `__oe_ecalls_table`.

```
...
ecall_table.ecalls = __oe_ecalls_table;
ecall_table.num_ecalls = __oe_ecalls_table_size;

if (args.function_id >= ecall_table.num_ecalls)
    OE_RAISE(OE_NOT_FOUND);

func = ecall_table.ecalls[args.function_id];
...

// Call the function.
func(
    input_buffer,
    args.input_buffer_size,
    output_buffer,
    args.output_buffer_size,
    &output_bytes_written);
```

After looking up based on the function id (`sample_fcn_id_sample_ecall`),
`oe_handle_call_enclave_function()` calls into the wrapper function `ecall_sample_ecall()`(defined in `sample_t.c`).
The wrapper function performs a series of checks, unmarshals the arguments, and invokes
the ECALL implemented by the enclave with the following code snippet.

```
/* Call user function. */
pargs_out->_retval = sample_ecall(
);
```

At this point, an ECALL is successfully dispatched to the enclave.

**OCALL Invocation**

The invocation of OCALLs is similar to that of ECALLs. The only difference is that
the array of the function pointers is defined as `__sample_ocall_function_table`
and is kept as part of the `enclave` struct.
More specifically, `sample_u.c` defines a wrapper function `oe_create_sample_enclave()` as follows.

```
oe_result_t oe_create_core_enclave(
    const char* path,
    oe_enclave_type_t type,
    uint32_t flags,
    const oe_enclave_setting_t* settings,
    uint32_t setting_count,
    oe_enclave_t** enclave)
{
    return oe_create_enclave(
               path,
               type,
               flags,
               settings,
               setting_count,
               __sample_ocall_function_table,
               1,
               enclave);
}
```

The wrapper function is used to create the enclave by the host. The `__sample_ocall_function_table`
is used during the initialization of the `enclave` struct as follows.

```
enclave->ocalls = (const oe_ocall_func_t*)ocall_table;
enclave->num_ocalls = ocall_count;
```

Similarly, the `oe_handle_call_host_function()` function uses these variables to handle the requests
of OCALLs.

```
...
ocall_table.ocalls = enclave->ocalls;
ocall_table.num_ocalls = enclave->num_ocalls;

if (args_ptr->function_id >= ocall_table.num_ocalls)
    OE_RAISE(OE_NOT_FOUND);

func = ocall_table.ocalls[args_ptr->function_id];
...

// Call the function.
func(
    args_ptr->input_buffer,
    args_ptr->input_buffer_size,
    args_ptr->output_buffer,
    args_ptr->output_buffer_size,
    &args_ptr->output_bytes_written);
```

**Interal EDL**

To use EDL files internally, the OE SDK has incorporated a workaround as follows.
Using wrappers files for both `_t.c` and `_u.c` files. Below, we take the internal EDL file `core.edl`
as an example to explain how these wrappers support an ECALL. The support of the OCALL works similarly.

**Wrapper of `core_t.c`**

The wrapper file of `core_t.c`, or `core_t_wrapper.c`, renames the hard-coded `__oe_ecalls_table`
and includes the `core_t.c` (see the following code snippet).

```
/* Rename the global ecalls table. */
#define __oe_ecalls_table __oe_core_ecalls_table
#define __oe_ecalls_table_size __oe_core_ecalls_table_size

...

/* Include the oeedger8r generated C file. The macros defined above customize
 * the generated code for internal use. */
#include "core_t.c"
```

In addition, `core_t_wrapper.c` implements a function as the following code snippet that
registers the table to an internal data structure.
This function is invoked by the `oecore` library during the enclave initialization.
With this, the enclave internally maintains multiple ECALL tables according to the number
of EDL files.

```
/* Registers the core ECALL function table. */
oe_result_t oe_register_core_ecall_function_table(void)
{
    const uint64_t table_id = OE_CORE_ECALL_FUNCTION_TABLE_ID;
    const oe_ecall_func_t* ecalls = __oe_core_ecalls_table;
    const size_t num_ecalls = __oe_core_ecalls_table_size;

    return oe_register_ecall_function_table(table_id, ecalls, num_ecalls);
}
```

**Wrapper of `core_u.c`**

The goal of the wrapper of `core_u.c`, or `core_u_wrapper.c`, is allowing the
ECALL stub code to pass the identifier of the ECALL table when making the ECALL.
To this end, `core_u_wrapper.c` replaces the `oe_call_host_function()` function
with the following code snippet.

```
/* Override oe_call_enclave_function() with _call_core_enclave_function(). */
#define oe_call_enclave_function _call_core_enclave_function

/* The ocall edge routines will use this function to route ecalls. */
static oe_result_t _call_core_enclave_function(
    oe_enclave_t* enclave,
    uint32_t function_id,
    const void* input_buffer,
    size_t input_buffer_size,
    void* output_buffer,
    size_t output_buffer_size,
    size_t* output_bytes_written)
{
    return oe_call_enclave_function_by_table_id(
        enclave,
        OE_CORE_ECALL_FUNCTION_TABLE_ID,
        function_id,
        input_buffer,
        input_buffer_size,
        output_buffer,
        output_buffer_size,
        output_bytes_written);
}
```

Both the host and the enclave share the definition of the `OE_CORE_ECALL_FUNCTION_TABLE_ID`,
which is a hard-coded value that represents the identifier of the table.
Upon receiving the request of the ECALL, `oe_handle_call_enclave_function()` locates
the table based on the table id and looks up the ECALL based on the function id
within the table. See the following code snippet from the `oe_handle_call_enclave_function()`
function.

```
// Resolve which ecall table to use.
if (args_ptr->table_id == OE_UINT64_MAX)
{
    ecall_table.ecalls = __oe_ecalls_table;
    ecall_table.num_ecalls = __oe_ecalls_table_size;
}
else
{
    if (args_ptr->table_id >= OE_MAX_ECALL_TABLES)
        OE_RAISE(OE_NOT_FOUND);

    ecall_table.ecalls = _ecall_tables[args_ptr->table_id].ecalls;
    ecall_table.num_ecalls = _ecall_tables[args_ptr->table_id].num_ecalls;

    if (!ecall_table.ecalls)
        OE_RAISE(OE_NOT_FOUND);
}
```

Limitation
---------

The current implementations poses a limitation to the scenario where the
host instantiates different enclaves that use the same set of ECALLs
(i.e., importing the same EDL files).
Taking the following case study for example.

**Case Study**

Assume the OE SDK provides two EDL files that allow enclaves to opt-in as follows.

```
// common_1.edl
enclave
{
    trusted
    {
        public void common_1_ecall();
    };
}
```

```
// common_2.edl
enclave
{
    trusted
    {
        public void common_2_ecall_1();
        public void common_2_ecall_2();
    };
}
```

Consider two enclaves, `boo` and `bar`. Their EDL files are defined as follows.

```
// foo.edl
enclave
{
    from "common_1.edl" import *;
    from "common_2.edl" import *;

    trusted
    {
        public void foo_ecall();
    };
}
```

```
// bar.edl
enclave
{
    from "common_2.edl" import *;
    from "common_1.edl" import *;

    trusted
    {
        public void bar_ecall();
    };
}
```

Note that both the EDL files import the two SDK-provided EDL files but in
different order. The resulting ECALL tables defeind in the
correspnding `_t.c` and `_u.c` files will be as follows.

- `foo` ECALL table
  ```
  oe_ecall_func_t __oe_ecalls_table[] = {
      (oe_ecall_func_t) ecall_common_1_ecall,
      (oe_ecall_func_t) ecall_common_2_ecall_1,
      (oe_ecall_func_t) ecall_common_2_ecall_2,
      (oe_ecall_func_t) ecall_foo_ecall
  };
  ```
- `bar` ECALL table
  ```
  oe_ecall_func_t __oe_ecalls_table[] = {
      (oe_ecall_func_t) ecall_common_2_ecall_1,
      (oe_ecall_func_t) ecall_common_2_ecall_2,
      (oe_ecall_func_t) ecall_common_1_ecall,
      (oe_ecall_func_t) ecall_bar_ecall
  };
  ```

In addition, both `foo_u.c` and `bar_u.c` will implement same wrapper functions
of the three imported functions. Assuming that we use *weak symbol* to avoid the
duplication of the wrapper functions (i.e., only one implementation of the functions is picked),
the invocation of these ECALLs to both enclaves ends up using the same function ids.

See the following host-side code snippet for an exmaple.
```
// ECALL to the enclave `foo`.
common_1_ecall(enclave_foo);

// ECALL to the enclave `bar`.
common_1_ecall(enclave_bar);
```

Since the host can have only one implementation of `ecall_common_1_ecall` (the wrapper function),
both invocations end up using the same function id, say `0`. However, this causes the mismatch
on the call into the enclave `bar` where the expected id should be `2`.

Proposed revision
-----------

The main goal of this proposal is to address the limitation that different enclaves on the
same host cannot import the same EDL files (with the same set of ECALLs). In addition,
the proposed revision aims to remove the needs of `_u_wrapper.c` and `_t_wrapper.c`,
which use uncommon practices (i.e., include the source file).

To meet these goals, this document proposes a two-phase revision.
Each phase requires separate reviews and implementation.

## Phase 1: Revise the ECALL Calling Mechanism

**Store ECALL by hash**

The main drawback of current implementation is using the table defined
in the `_u.c/_t.c` that serves as the contract between both ends.
Given that the rule of importing `EDL` files is flexible, the resulting
ECALL table is not determinstic (i.e., can be any order based on how
EDL files are imported).

To solve the problem, this phase proposes to maintain a single table
that stores the function pointer along with its hash (e.g., the hash of the function name).
Take the previous example with two enclaves, the ECALL tables now beome:

- `foo` ECALL table
  ```
  oe_ecall_struct_t __oe_ecalls_table[] = {
      { (oe_ecall_func_t) ecall_common_1_ecall, 3934942254 },
      { (oe_ecall_func_t) ecall_common_2_ecall_1, 1220950296 },
      { (oe_ecall_func_t) ecall_common_2_ecall_2, 3520030882 },
      { (oe_ecall_func_t) ecall_foo_ecall, 2696310045 }
  };
  ```
- `bar` ECALL table
  ```
  oe_ecall_struct_t __oe_ecalls_table[] = {
      { (oe_ecall_func_t) ecall_common_2_ecall_1, 1220950296 },
      { (oe_ecall_func_t) ecall_common_2_ecall_2, 3520030882 },
      { (oe_ecall_func_t) ecall_common_1_ecall, 3934942254 },
      { (oe_ecall_func_t) ecall_bar_ecall, 4007252781 }
  };
  ```

The the invocation of an ECALL can then be based on the hash instead of the hard-coded
function id.

**Cache the ECALL Id for the Const-Time Look-Up**

Instead of implementing hash table that cannot guarantee constant-time look-up, each enclave stores the ECALLs
in an array (`ecall_table`) of `oe_ecall_struct_t`, which is defined as follows.

```
typedef struct oe_ecall_struct_t
{
    oe_ecall_func_t ecall;
    uint64_t hash;
} oe_ecall_struct_t;

oe_ecall_struct_t _ecall_table[OE_MAX_ECALLS];
```

In previous example, the `ecall_table` of two enclaves are as follows.
- `foo`
  ```
  ecall_table[0]: { ecall_common_1_ecall, 3934942254 }
  ecall_table[1]: { ecall_common_2_ecall_1, 1220950296 }
  ecall_table[2]: { ecall_common_2_ecall_2, 3520030882 }
  ecall_table[3]: { ecall_foo_ecall, 2696310045 }
  ```
- `bar`
  ```
  ecall_table[0]: { ecall_common_2_ecall_1, 1220950296 }
  ecall_table[1]: { ecall_common_2_ecall_2, 3520030882 }
  ecall_table[2]: { ecall_common_1_ecall, 3934942254 }
  ecall_table[3]: { ecall_bar_ecall, 4007252781 }
  ```
Achieving the constant-time look-up means that the look-up should use id instead of hash.
However, from the above example, we can see that the id of the same ECALL are different across
enclaves.



  Because a single host may interact with multiple enclaves, we cannot directly cache the ECALL id inside an ECALL wrapper;
  i.e., the host may use the same ECALL wrapper to dispatch the request to different enclaves. As a result, we need to
  cache the id per enclave. More specifically, the host maintains an id caching table of ECALLs per `enclave` struct. Note that
  this table includes all the ECALLs from multiple enclaves such that every `enclave` structs have the same table.
  
  Take a similar example of two enclaves: `enclave_foo` and `enclave_bar`. Both of the enclaves implement
  the ECALL `sample_ecall`, but with different ids (e.g., `1` in `enclave_foo` and `2` in `enclave_bar`).
  To cache the id per enclave, the `enclave` structs of both enclaves, `enclave_foo` and `_enclave_bar`,
  on the host maintains the same table `ecall_id_table`. As a result, the index of `sample_ecall` in
  `enclave_foo->ecall_id_table` and `enclave_bar->ecall_id_table` is the same, which allows for caching
  the ECALL id on the per enclave basis.
  
  With this, the ECALL wrapper looks up the id to the per-enclave caching table and then obtains
  the ECALL id from the enclave (via a specialized ECALLs) for the first invocation.
  In the subsequent invocations, the ECALL wrapper uses the cached caching table id and per-enclave
  ECALL id to make the ECALL. See the following code snippet for an example.
  
  ```
  oe_result_t oe_verify_report_ecall(
    oe_enclave_t* enclave,
    oe_result_t* _retval,
    const void* report,
    size_t report_size)
  {
      oe_result_t _result = OE_FAILURE;

      /* CRC32 of oe_verify_report_ecall */
      const uint32_t _function_hash = 3802944385;

      /* Used to cache the index to the id caching table. */
      static int _caching_table_id = OE_HOST_ECALL_ID_NULL;

      int _ecall_id = -1;
      
      ...
      
      /* Check if the index is cached. */
      if (_caching_table_id == OE_HOST_ECALL_ID_NULL)
      {
        _caching_table_id = oe_host_get_ecall_id_by_hash(
            enclave,
            _function_hash);
      }

      ...
      
      /* Obtain the ecall id from the caching table. */
      _ecall_id = oe_get_ecall_function_id(enclave, _caching_table_id);
      if (_ecall_id == -1)
      {
          oe_call_enclave_get_function_id_by_hash(
              enclave,
              _function_hash,
              &_ecall_id);
          oe_set_ecall_function_id(enclave, _caching_table_id, _ecall_id);
      }
     
      /* Call enclave function. */
      if ((_result = oe_call_enclave_function(
             enclave,
            (uint64_t) _ecall_id,
            (uint64_t) _function_hash,
            _input_buffer,
            _input_buffer_size,
            _output_buffer,
            _output_buffer_size,
            &_output_bytes_written)) != OE_OK)
          goto done;
          
      ...
  }
  ```
**Extening the idea to OCALLs**

Although the OCALLs do not suffer the same limitation as ECALLs, we could
extend the idea to exclude the needs of using wrapper files for `_t.c` and `_u.c`
completely. Recall that the wrapper are needed to replace the stub code on
both 

**Add the registration functions of ECALLs and OCALLs in `_t.c` and `_u.c`**

Instead of using wrappers for `_t.c` and `_u.c` files, each `_t.c` or `_u.c` now
includes functions that register the list of OCALLs/ECALLs by passing the function
pointers and the hashes of function names. See the following example.
  
```
/**** ECALL function table. ****/
static oe_ecall_struct_t __oe_ecall_table[] = {
    { (oe_ecall_func_t) ecall_oe_verify_report_ecall, 3802944385 },
    { (oe_ecall_func_t) ecall_oe_get_public_key_ecall, 1967956880 },
    { (oe_ecall_func_t) ecall_oe_get_public_key_by_policy_ecall, 550431498 },
    { (oe_ecall_func_t) ecall_oe_log_init_ecall, 4072068939 }
};
static uint32_t __oe_ecall_table_size = 4;

/* Ecall table registration function. */
void oe_register_core_enclave_functions(void)
{
    oe_register_enclave_functions_internal(
        __oe_ecall_table,
        __oe_ecall_table_size);
}
#ifndef OE_INTERNAL_EDL
EDGER8R_WEAK_ALIAS(oe_register_core_enclave_functions, oe_register_enclave_functions);
#endif
```

- Caching an OCALL id.

  Because an enclave only interacts with a single host, the case of OCALL wrapper is straightforward:
  caching the id within the implementation of the wrapper.

  ```
  oe_result_t oe_log_ocall(
      uint32_t log_level,
      const char* message)
    {
        oe_result_t _result = OE_FAILURE;

        /* CRC32 of oe_log_ocall */
        const uint32_t _function_hash = 3195194105;

        /* Used to cache the ocall id. */
        static int _ocall_id = OE_OCALL_ID_NULL;
        
        ...
        
        /* Check if the ocall id is cached. */
        if (_ocall_id == OE_OCALL_ID_NULL)
          _ocall_id = oe_host_get_ocall_id_by_hash(_function_hash);

        /* Call host function. */
        if ((_result = oe_call_host_function(
             (uint64_t) _ocall_id,
             (uint64_t) _function_hash,
             _input_buffer,
             _input_buffer_size,
             _output_buffer,
             _output_buffer_size,
             &_output_bytes_written)) != OE_OK)
            goto done;

        ...
     }
  ```

Authors
-------

- Ming-Wei Shih <mishih@microsoft.com>
