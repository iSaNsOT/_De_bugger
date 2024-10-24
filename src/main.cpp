#include <vector>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/personality.h>
#include <unistd.h>
#include <sstream>
#include <iostream>
#include <iomanip>

#include "linenoise.h"

#include "debugger.hpp"
#include "registers.hpp"

using namespace dbg;

int main (int argc, char *argv[]) {
    if(argc < 2){
        std::cerr << "You must specify name of the program to debug\n";
        return -1;
    }
    
    auto progName = argv[1];

    auto pid = fork();

    if(pid == 0){
        // child, execute the program (debugee)
        long pterr = ptrace(PTRACE_TRACEME, 0, nullptr, nullptr);
        if(pterr < 0){
            std::cerr << "Error in ptrace(PTRACE_TRACEME)";
            return -1;
        }
        int exerr = execl(progName, progName, nullptr);
        if(exerr < 0){
            std::cerr << "Error in execl()";
            return -1;
        }
    }
    else if (pid >= 1){
        // parent, execute debugger
        std::cout << "Started debugging process " << pid << '\n';
        debugger dbg{progName, pid};
        dbg.run();
    }
    
    return 0;
}

uint64_t debugger::readMemory(uint64_t address) {
    return ptrace(PTRACE_PEEKDATA, m_pid, address, nullptr);
}

void debugger::writeMemory(uint64_t address, uint64_t value) {
    ptrace(PTRACE_POKEDATA, m_pid, address, value);
}

uint64_t debugger::getProgramCounter() {
    return getRegisterValue(m_pid, reg::rip);
}

void debugger::setProgramCounter(uint64_t pc) {
    setRegisterValue(m_pid, reg::rip, pc);
}

void debugger::stepOverBreakpoint() {
    // - 1 because execution will go past the breakpoint
    auto possible_breakpoint_location = getProgramCounter() - 1;

    if (m_breakpoints.count(possible_breakpoint_location)) {
        auto& bp = m_breakpoints[possible_breakpoint_location];

        if (bp.is_enabled()) {
            auto previous_instruction_address = possible_breakpoint_location;
            setProgramCounter(previous_instruction_address);

            bp.disable();
            ptrace(PTRACE_SINGLESTEP, m_pid, nullptr, nullptr);
            waitForSignal();
            bp.enable();
        }
    }
}

void debugger::waitForSignal() {
    int wait_status;
    auto options = 0;
    waitpid(m_pid, &wait_status, options);
}

void debugger::dumpRegisters(){
    for(const auto& rd : gRegisterDescriptors){
        std::cout << rd.name << " 0x" << std::setfill('0') << std::setw(16) << std::hex << getRegisterValue(m_pid, rd.r) << std::endl;
    }
}

std::vector<std::string> split(const std::string &s, char delimiter) {
    std::vector<std::string> out{};
    std::stringstream ss {s};
    std::string item;

    while (std::getline(ss,item,delimiter)) {
        out.push_back(item);
    }

    return out;
}

bool isPrefix(const std::string& s, const std::string& of) {
    if (s.size() > of.size()) return false;
    return std::equal(s.begin(), s.end(), of.begin());
}
void debugger::handleCommand(const std::string &line){
    auto args = split(line, ' ');
    auto command = args[0];

    if(isPrefix(command, "continue")){
        continueExecution();
    }
    else if(isPrefix(command, "break")){
        std::string addr {args[1], 2}; // remove the 0x prefix, first two characters from the input address
        setBreakpointAtAddress(std::stol(addr, 0, 16));
    }
    else if(isPrefix(command, "register")){
        if (isPrefix(args[1], "dump")){
            dumpRegisters();
        }
        // Ex -> register read rax
        else if(isPrefix(args[1], "read")){
            auto reg = getRegisterFromName(args[2]);
            std::cout << getRegisterValue(m_pid, reg) << std::endl;
        }
        // Ex -> register write rax 0x42
        else if(isPrefix(args[1], "write")){
            auto reg = getRegisterFromName(args[2]);
            std::string val {args[3], 2}; // remove the 0x prefix, first two characters from the input address
            setRegisterValue(m_pid, reg, std::stol(val, 0, 16));
        }
    }
    else if(isPrefix(command, "memory")){
        std::string addr {args[2], 2}; // remove the 0x prefix, first two characters from the input address
        if(isPrefix(args[1], "read")){
            std::cout << std::hex << readMemory(std::stol(addr, 0, 16)) << std::endl;
        }
        else if(isPrefix(args[1], "write")){
            std::string val {args[3], 2}; // remove the 0x prefix, first two characters from the input address
            writeMemory(std::stol(addr, 0, 16), std::stol(val, 0, 16));
        }
    }
    else {
        std::cerr << "Unknown command\n";
    }
}

void debugger::continueExecution(){
    stepOverBreakpoint();
    ptrace(PTRACE_CONT, m_pid, nullptr, nullptr);
    waitForSignal();
}

void debugger::setBreakpointAtAddress(std::intptr_t addr){
    std::cout << "Setting breakpoint at address 0x" << std::hex << addr << std::endl;
    breakpoint bp{m_pid, addr};
    bp.enable();
    m_breakpoints[addr] = bp;
}

void debugger::run(){
    int waitStatus;
    auto options = 0;
    waitpid(m_pid, &waitStatus, options);

    char *line = nullptr;
    while((line = linenoise("dbg->")) != nullptr){
        handleCommand(line);
        linenoiseHistoryAdd(line);
        linenoiseFree(line);
    }
}