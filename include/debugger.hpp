#ifndef DBG_DEBUGGER_HPP
#define DBG_DEBUGGER_HPP

#include <utility>
#include <string>
#include <linux/types.h>
#include <unordered_map>
#include <fcntl.h>

#include "breakpoint.hpp"
#include "dwarf/dwarf++.hh"
#include "elf/elf++.hh"

namespace dbg{
    class debugger {
    public:
        debugger (std::string prog_name, pid_t pid)
            : m_prog_name{std::move(prog_name)}, m_pid{pid} {
                auto fd = open(m_prog_name.c_str(), O_RDONLY); // no ifstream, UNIX file descriptor to pass to nmap

                m_elf = elf::elf{elf::create_mmap_loader(fd)};
                m_dwarf = dwarf::dwarf{dwarf::elf::create_loader(m_elf)};
            }

        void run();
        void setBreakpointAtAddress(std::intptr_t addr);
        void dumpRegisters();
        void printSource(const std::string& file_name, unsigned line, unsigned n_lines_context=2);
        void singleStepInstruction();
        void singleStepInstructionWithBreakpointCheck();
        void removeBreakpointAtAddress(std::intptr_t addr);
        void stepIn();
        void stepOut();
        void stepOver();

    private:
        std::string m_prog_name;
        pid_t m_pid;
        std::unordered_map<std::intptr_t, breakpoint> m_breakpoints;
        elf::elf m_elf;
        dwarf::dwarf m_dwarf;
        uint64_t m_load_address = 0;

        void handleCommand(const std::string &line);
        void continueExecution();
        auto getProgramCounter() -> uint64_t;
        void setProgramCounter(uint64_t pc);
        auto readMemory(uint64_t address) -> uint64_t ;
        void writeMemory(uint64_t address, uint64_t value);
        void stepOverBreakpoint();
        void waitForSignal();
        
        auto getSignalInfo() -> siginfo_t;
        void handleSigtrap(siginfo_t info);

        void initialiseLoadAddress();
        uint64_t offsetLoadAddress(uint64_t addr);
        uint64_t offsetDwarfAddress(uint64_t addr);

        auto getFunctionFromPc(uint64_t pc) -> dwarf::die;
        auto getLineEntryFromPc(uint64_t pc) -> dwarf::line_table::iterator;
        uint64_t getOffsetPc();
    };
}
#endif