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

Limitations
---------

The current implementation poses the following limitations.

- Single enclave cannot include multiple EDL files.

  According to the implementation, the `oecore` library
directly links against the `__oe_ecalls_table` defined in a `_t.c` file.
Therefore, the current logic cannot handle the case of including
multiple `_t.c` files.

- Multiple enclaves on the same host cannot use/import the same EDL file.

  Importing the same EDL file results in generating the same stub code in a
`_u.c` file. Including multiple such `_u.c` files causes the conflicts
during compile-time.

### Existing workaround and its limitation

To use EDL files internally, the OE SDK has incorporated a workaround to the first limitation:
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

**The Limitation of Per-EDL Tables**

The workaround introduces per-EDL tables that address the limitation that
an enclave cannot include multiple EDL files. However, this approach
does not scale well when extending it to address the other limitation:
multiple enclaves on the same host cannot import/use the same EDL file
(e.g., including the same set of ECALLs).

Considering an example with two enclaves, say `enclave_foo` and `enclave_bar`.
Each enclave defines its own EDL file with a different number of ECALLs.
In addition, both the EDL files import the same EDL file (the same `sample.edl` as above).
As a result, the corresponding ECALL tables (defined in each `_t.c` file) include
the wrapper function of `sample_ecall` but with different function id (because
the number of ECALLs is different).
Assuming that we use *weak symbol* to avoid the naming conflict of
the wrapper function (i.e., only one implementation of the functions is picked),
the invocation of `sample_ecall` to both enclaves ends up using the same
table id and function id and potentially causing a mismatch;
i.e., the enclave may use the wrong table id or function id to look up the ECALL.

Proposed revision
-----------

To address two limitations more fundamentally, this document proposes to
use a single table that includes ECALLs or OCALLs in multiple EDL files.
This section describes the detail of the design and considerations.

**Maintain Single Table for ECALL and OCALL**

Instead of adopting the per-EDL tables, maintaining a single table (i.e., one
OCALL table and one ECALL table) provides finer granularity to keep track
of ECALLs or OCALLs from multiple EDL files that are either imported or directly included.
To avoid duplicated entries, each ECALL or OCALL is registered by its hash of the name.
  
**Add the registration functions of ECALLs and OCALLs in `_t.c` and `_u.c`**

Instead of using wrappers for `_t.c` and `_u.c` files, each `_t.c` or `_u.c` now
includes functions that register the list of OCALLs/ECALLs by passing the function
pointers and the hashes of function names. See the following example.
  
```
static oe_ecall_func_t __oe_ecalls_table[] = {
    (oe_ecall_func_t) ecall_oe_verify_report_ecall,
    (oe_ecall_func_t) ecall_oe_get_public_key_ecall,
    (oe_ecall_func_t) ecall_oe_get_public_key_by_policy_ecall,
    (oe_ecall_func_t) ecall_oe_log_init_ecall
};

static uint32_t __oe_ecalls_hash_list[] = {
    3802944385 /* CRC32 of oe_verify_report_ecall. */,
    1967956880 /* CRC32 of oe_get_public_key_ecall. */,
    550431498 /* CRC32 of oe_get_public_key_by_policy_ecall. */,
    4072068939 /* CRC32 of oe_log_init_ecall. */
};

static size_t __oe_ecalls_table_size = OE_COUNTOF(__oe_ecalls_table);

/* Ecall table registration function. */
static void register_core_ecall_functions()
{
    oe_register_ecall_functions(
      __oe_ecalls_table,
      __oe_ecalls_hash_list,
      __oe_ecalls_table_size);
}
```

Each table entry is then defined as the following struct.

```
typedef struct _oe_ocall_t {
    oe_ocall_func_t ocall;
    uint32_t hash;
} oe_ocall_t;
```

**Maintain the List of Registration Functions**

Each registration function in a EDL file is added to a list via the constructor.
On Linux, we can do this via ` __attribute__((constructor))` as follows.
We can use an equivalent approach for the constructor on Windows.
```
/* Constructor to register the callback. */
 __attribute__((constructor)) static void core_ecall_functions_constructor()
{
    oe_ecall_init(register_core_ecall_functions);
}
```

The list of registration functions can then be invoked during the host and enclave
initialization.
  
**Cache the Function Id for the Const-Time Look-Up**

One important property of current implementation is the const-time function look-up that
this proposal would like to maintain. To this end, the design is obtaining the id by hash
in the first invocation and caching the id for subsequent ones.

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

- Caching an ECALL id.
  
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
  

Authors
-------

- Ming-Wei Shih <mishih@microsoft.com>
