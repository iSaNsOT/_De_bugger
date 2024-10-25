#include <vector>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/personality.h>
#include <unistd.h>
#include <sstream>
#include <fstream>
#include <iostream>
#include <iomanip>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

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
        // Child, execute the program (debugee)
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
        // Parent, execute debugger
        std::cout << "Started debugging process " << pid << '\n';
        debugger dbg{progName, pid};
        dbg.run();
    }
    
    return 0;
}

void debugger::initialiseLoadAddress() {
   // If this is a dynamic library (e.g. PIE)
   if (m_elf.get_hdr().type == elf::et::dyn) {
      // The load address is found in /proc/<pid>/maps
      std::ifstream map("/proc/" + std::to_string(m_pid) + "/maps");

      // Read the first address from the file
      std::string addr;
      std::getline(map, addr, '-');

      m_load_address = std::stoi(addr, 0, 16);
   }
}

uint64_t debugger::offsetLoadAddress(uint64_t addr) {
   return addr - m_load_address;
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

dwarf::die debugger::getFunctionFromPc(uint64_t pc) {
    for (const auto &cu : m_dwarf.compilation_units()) {
        if (die_pc_range(cu.root()).contains(pc)) {
            for (const auto &die : cu.root()) {
                if (die.tag == dwarf::DW_TAG::subprogram) {
                    if (die_pc_range(die).contains(pc)) {
                        return die;
                    }
                }
            }
        }
    }
    throw std::out_of_range{"Cannot find function"};
}

dwarf::line_table::iterator debugger::getLineEntryFromPc(uint64_t pc) {
    for (auto &cu : m_dwarf.compilation_units()) {
        if (die_pc_range(cu.root()).contains(pc)) {
            auto &lt = cu.get_line_table();
            auto it = lt.find_address(pc);
            if (it == lt.end()) {
                throw std::out_of_range{"Cannot find line entry"};
            } else {
                return it;
            }
        }
    }
    throw std::out_of_range{"Cannot find line entry"};
}

void debugger::printSource(const std::string& file_name, unsigned line, unsigned n_lines_context) {
    std::ifstream file {file_name};

    // Work out a window around the desired line
    auto start_line = line <= n_lines_context ? 1 : line - n_lines_context;
    auto end_line = line + n_lines_context + (line < n_lines_context ? n_lines_context - line : 0) + 1;

    char c{};
    auto current_line = 1u;
    // Skip lines up until start_line
    while (current_line != start_line && file.get(c)) {
        if (c == '\n') {
            ++current_line;
        }
    }

    // Output cursor if we're at the current line
    std::cout << (current_line==line ? "> " : "  ");

    // Write lines up until end_line
    while (current_line <= end_line && file.get(c)) {
        std::cout << c;
        if (c == '\n') {
            ++current_line;
            // Output cursor if we're at the current line
            std::cout << (current_line==line ? "> " : "  ");
        }
    }

    // Write newline and make sure that the stream is flushed properly
    std::cout << std::endl;
}

// NOTE: siginfo_t provides the following information:
/*
siginfo_t {
    int      si_signo;    * Signal number *
    int      si_errno;    * An errno value *
    int      si_code;     * Signal code *
    int      si_trapno;   * Trap number that caused
                              hardware-generated signal
                              (unused on most architectures) *
    pid_t    si_pid;      * Sending process ID *
    uid_t    si_uid;      * Real user ID of sending process *
    int      si_status;   * Exit value or signal *
    clock_t  si_utime;    * User time consumed *
    clock_t  si_stime;    * System time consumed *
    sigval_t si_value;    * Signal value *
    int      si_int;      * POSIX.1b signal *
    void    *si_ptr;      * POSIX.1b signal *
    int      si_overrun;  * Timer overrun count;
                              POSIX.1b timers *
    int      si_timerid;  * Timer ID; POSIX.1b timers *
    void    *si_addr;     * Memory location which caused fault *
    long     si_band;     * Band event (was int in
                              glibc 2.3.2 and earlier) *
    int      si_fd;       * File descriptor *
    short    si_addr_lsb; * Least significant bit of address
                              (since Linux 2.6.32) *
    void    *si_lower;    * Lower bound when address violation
                              occurred (since Linux 3.19) *
    void    *si_upper;    * Upper bound when address violation
                              occurred (since Linux 3.19) *
    int      si_pkey;     * Protection key on PTE that caused
                              fault (since Linux 4.6) *
    void    *si_call_addr;* Address of system call instruction
                              (since Linux 3.5) *
    int      si_syscall;  * Number of attempted system call
                              (since Linux 3.5) *
    unsigned int si_arch; * Architecture of attempted system call
                              (since Linux 3.5) *
}
*/
siginfo_t debugger::getSignalInfo() {
    siginfo_t info;
    ptrace(PTRACE_GETSIGINFO, m_pid, nullptr, &info);
    return info;
}

void debugger::handleSigtrap(siginfo_t info) {
    switch (info.si_code) {
    // One of these will be set if a breakpoint was hit
    case SI_KERNEL:
    case TRAP_BRKPT:
    {
        setProgramCounter(getProgramCounter()-1); // Program Counter back where it should be
        std::cout << "Hit breakpoint at address 0x" << std::hex << getProgramCounter() << std::endl;
        auto offset_pc = offsetLoadAddress(getProgramCounter()); // Offset the pc for querying DWARF
        auto line_entry = getLineEntryFromPc(offset_pc);
        printSource(line_entry->file->path, line_entry->line);
        return;
    }
    // This will be set if the signal was sent by single stepping
    case TRAP_TRACE:
        return;
    default:
        std::cout << "Unknown SIGTRAP code " << info.si_code << std::endl;
        return;
    }
}

void debugger::stepOverBreakpoint() {
    if (m_breakpoints.count(getProgramCounter())) {
        auto& bp = m_breakpoints[getProgramCounter()];

        if (bp.is_enabled()) {
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

    auto siginfo = getSignalInfo();

    switch (siginfo.si_signo) {
        case SIGTRAP:
            handleSigtrap(siginfo);
            break;
        case SIGSEGV:
            std::cout << "Yay, segfault. Reason: " << siginfo.si_code << std::endl;
            break;
        default:
            std::cout << "Got signal " << strsignal(siginfo.si_signo) << std::endl;
    }
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
        std::string addr {args[1], 2}; // Remove the 0x prefix, first two characters from the input address
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
        std::string addr {args[2], 2}; // Remove the 0x prefix, first two characters from the input address
        if(isPrefix(args[1], "read")){
            std::cout << std::hex << readMemory(std::stol(addr, 0, 16)) << std::endl;
        }
        else if(isPrefix(args[1], "write")){
            std::string val {args[3], 2}; // Remove the 0x prefix, first two characters from the input address
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

    waitForSignal();
    initialiseLoadAddress();

    char *line = nullptr;
    while((line = linenoise("dbg->")) != nullptr){
        handleCommand(line);
        linenoiseHistoryAdd(line);
        linenoiseFree(line);
    }
}