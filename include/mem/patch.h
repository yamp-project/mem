#ifndef MEM_PATCH_H
#define MEM_PATCH_H

#include "protect.h"

namespace mem
{
    template <typename T>
    MEM_STRONG_INLINE constexpr void pointer::put(const T& value) const noexcept
    {
        void* addr = reinterpret_cast<void*>(value_);
        prot_flags old_flags;

        protect_modify(addr, sizeof(T), prot_flags::RW, &old_flags);
        memcpy(addr, &value, sizeof(T));
        protect_modify(addr, sizeof(T), old_flags);
    }

    template <size_t N>
    MEM_STRONG_INLINE constexpr void pointer::put(uint8_t (&bytes)[N]) const noexcept
    {
        put<uint8_t[N]>(bytes);
    }

    MEM_STRONG_INLINE void pointer::put(unsigned char* bytes, size_t size) const noexcept
    {
        void* addr = reinterpret_cast<void*>(value_);
        prot_flags old_flags;

        protect_modify(addr, size, prot_flags::RW, &old_flags);
        std::memcpy(addr, bytes, size);
        protect_modify(addr, size, old_flags);
    }

    MEM_STRONG_INLINE void pointer::nop(size_t len, unsigned char* modified_bytes = nullptr) const noexcept
    {
        void* addr = reinterpret_cast<void*>(value_);
        prot_flags old_flags;

        protect_modify(addr, len, prot_flags::RW, &old_flags);
        if (modified_bytes)
        {
            memcpy_s(modified_bytes, len, addr, len);
        }

        memset(addr, 0x90, len);
        protect_modify(addr, len, old_flags);
    }

    MEM_STRONG_INLINE void pointer::nop(size_t len, std::vector<unsigned char>* modified_bytes) const noexcept
    {
        nop(len, modified_bytes ? modified_bytes->data() : nullptr);
    }
} // namespace mem

#endif // MEM_PATCH_H
