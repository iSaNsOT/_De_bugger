#ifndef DBG_DEBUGGER_HPP
#define DBG_DEBUGGER_HPP

#include <utility>
#include <string>
#include <linux/types.h>
#include <unordered_map>

#include "breakpoint.hpp"

namespace dbg{
    class debugger {
    public:
        debugger (std::string prog_name, pid_t pid)
            : m_prog_name{std::move(prog_name)}, m_pid{pid} {}

        void run();
        void setBreakpointAtAddress(std::intptr_t addr);
        void dumpRegisters();

    private:
        std::string m_prog_name;
        pid_t m_pid;
        std::unordered_map<std::intptr_t, breakpoint> m_breakpoints;

        void handleCommand(const std::string &line);
        void continueExecution();

        auto getProgramCounter() -> uint64_t;
        void setProgramCounter(uint64_t pc);
        auto readMemory(uint64_t address) -> uint64_t ;
        void writeMemory(uint64_t address, uint64_t value);
        void stepOverBreakpoint();
        void waitForSignal();
    };
}
#endif