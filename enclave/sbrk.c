#include <openenclave/enclave.h>
#include <openenclave/bits/globals.h>

void* OE_Sbrk(ptrdiff_t increment);

void* OE_Sbrk(ptrdiff_t increment)
{
    static unsigned char* _heapNext;
    static OE_Spinlock _lock = OE_SPINLOCK_INITIALIZER;
    void* ptr = NULL;

    OE_SpinLock(&_lock);
    {
        size_t remaining;

        if (!_heapNext)
            _heapNext = (unsigned char*)__OE_GetHeapBase();

        remaining = (unsigned char*)__OE_GetHeapEnd() - _heapNext;

        if (increment <= remaining)
        {
            ptr = _heapNext;
            _heapNext += increment;
        }
    }
    OE_SpinUnlock(&_lock);

    return ptr;
}
