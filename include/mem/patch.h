#ifndef MEM_PATCH_H
#define MEM_PATCH_H

#include "protect.h"

namespace mem
{
    MEM_STRONG_INLINE pointer* pointer::virtual_mem() noexcept
    {
        static pointer _virtualmem((uintptr_t)0);
        return &_virtualmem;
    }

    MEM_STRONG_INLINE pointer pointer::get_virtual_mem(size_t size) noexcept
    {
        static pointer* current = virtual_mem();

        while (current->value_ % 16) {
            current->value_ += 1;
        }

        pointer res(current);
        current->value_ += size;
        return res;
    }

    template <typename T>
    MEM_STRONG_INLINE constexpr void pointer::put(const T& value) const noexcept
    {
        void* addr = reinterpret_cast<void*>(value_);
        prot_flags old_flags {};

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
            std::memcpy(modified_bytes, addr, len);
        }

        std::memset(addr, 0x90, len);
        protect_modify(addr, len, old_flags);
    }

    MEM_STRONG_INLINE void pointer::nop(size_t len, std::vector<unsigned char>* modified_bytes) const noexcept
    {
        if (modified_bytes)
        {
            modified_bytes->resize(len);
            nop(len, modified_bytes->data());
        }
        else
        {
            nop(len);
        }
    }

    MEM_STRONG_INLINE void pointer::ret() const noexcept
    {
        put<uint8_t>(0xC3);
    }

    MEM_STRONG_INLINE void pointer::make_jmp(uintptr_t func) const noexcept
    {
        pointer(value_).put<uint16_t>(0xB848);
        pointer(value_ + 2).put<uintptr_t>(func);
        pointer(value_ + 10).put<uint16_t>(0xE0FF);
    }

    MEM_STRONG_INLINE void pointer::make_jmp_ret(void* func) const noexcept
    {
        make_jmp_ret((uintptr_t)func);
    }

    MEM_STRONG_INLINE void pointer::make_jmp_ret(uintptr_t func) const noexcept
    {
        pointer(value_).put<uint16_t>(0xB848);
        pointer(value_ + 2).put<uintptr_t>(func);
        pointer(value_ + 10).put<uint16_t>(0xC350);
    }

    MEM_STRONG_INLINE void pointer::make_call(uintptr_t func) const noexcept
    {
        put<uint8_t>(0xE8);
        pointer(value_ + 1).put(int32_t(func - value_ - 5));
    }

    MEM_STRONG_INLINE void pointer::set_call(void* func, bool ret = false) const noexcept
    {
        pointer jmpMem = get_virtual_mem(12);
        if(ret) jmpMem.make_jmp_ret((uintptr_t)func);
        else jmpMem.make_jmp((uintptr_t)func);

        make_call(jmpMem.value_);
    }
} // namespace mem

#endif // MEM_PATCH_H
