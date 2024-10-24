#ifndef DBG_REGISTERS_HPP
#define DBG_REGISTERS_HPP

#include <sys/user.h>
#include <algorithm>
#include <array>

namespace dbg{
    enum class reg{
        rax, rbx, rcx, rdx,
        rdi, rsi, rbp, rsp,
        r8, r9, r10, r11,
        r12, r13, r14, r15,
        rip, rflags, cs, orig_rax,
        fs_base, gs_base,
        fs, gs, ss, ds, es
    };

    static constexpr std::size_t nRegisters = 27;

    struct regDescriptor{
        reg r;
        int dwarf_r;
        std::string name;
    };

    // NOTE: usr/include/sys/user.h for layout of registers in user regs struct
    static const std::array<regDescriptor, nRegisters> gRegisterDescriptors {{
        { reg::r15, 15, "r15" },
        { reg::r14, 14, "r14" },
        { reg::r13, 13, "r13" },
        { reg::r12, 12, "r12" },
        { reg::rbp, 6, "rbp" },
        { reg::rbx, 3, "rbx" },
        { reg::r11, 11, "r11" },
        { reg::r10, 10, "r10" },
        { reg::r9, 9, "r9" },
        { reg::r8, 8, "r8" },
        { reg::rax, 0, "rax" },
        { reg::rcx, 2, "rcx" },
        { reg::rdx, 1, "rdx" },
        { reg::rsi, 4, "rsi" },
        { reg::rdi, 5, "rdi" },
        { reg::orig_rax, -1, "orig_rax" },
        { reg::rip, -1, "rip" },
        { reg::cs, 51, "cs" },
        { reg::rflags, 49, "eflags" },
        { reg::rsp, 7, "rsp" },
        { reg::ss, 52, "ss" },
        { reg::fs_base, 58, "fs_base" },
        { reg::gs_base, 59, "gs_base" },
        { reg::ds, 53, "ds" },
        { reg::es, 50, "es" },
        { reg::fs, 54, "fs" },
        { reg::gs, 55, "gs" }
    }};

    uint64_t getRegisterValue(pid_t pid, reg r){
        user_regs_struct regs;
        ptrace(PTRACE_GETREGS, pid, nullptr, &regs);
        auto it = std::find_if(std::begin(gRegisterDescriptors), std::end(gRegisterDescriptors), [r](auto&& rd){ return rd.r == r; });
        return *(reinterpret_cast<uint64_t*>(&regs) + (it - std::begin(gRegisterDescriptors)));
    }

    void setRegisterValue(pid_t pid, reg r, uint64_t value){
        user_regs_struct regs;
        ptrace(PTRACE_GETREGS, pid, nullptr, &regs);
        auto it = std::find_if(std::begin(gRegisterDescriptors), std::end(gRegisterDescriptors), [r](auto&& rd){ return rd.r == r; });
        *(reinterpret_cast<uint64_t*>(&regs) + (it - std::begin(gRegisterDescriptors))) = value;
        ptrace(PTRACE_SETREGS, pid, nullptr, &regs);
    }

    uint64_t getRegisterValueFromDwarf(pid_t pid, unsigned regnum){
        auto it = std::find_if(std::begin(gRegisterDescriptors), std::end(gRegisterDescriptors), [regnum](auto&& rd){ return rd.dwarf_r == regnum; });
        if(it == std::end(gRegisterDescriptors)){
            throw std::out_of_range{"Unknown dwarf register"};
        }
        return getRegisterValue(pid, it->r);
    }

    std::string getRegisterName(reg r){
        auto it = std::find_if(std::begin(gRegisterDescriptors), std::end(gRegisterDescriptors), [r](auto&& rd){ return rd.r == r; });
        return it->name;
    }

    reg getRegisterFromName(const std::string& name){
        auto it = std::find_if(std::begin(gRegisterDescriptors), std::end(gRegisterDescriptors), [name](auto&& rd){ return rd.name == name; });
        return it->r;
    }
}

#endif