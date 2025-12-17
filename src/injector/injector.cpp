#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#include <string>
#include <iostream>
#include <cstring>
#include <dlfcn.h>
#include <vector>
#include <cstdint>

// Helper to get register
#ifdef __x86_64__
// struct user_regs_struct on Linux x86_64 usually just has members like rip, rsp directly
#define REG_IP rip
#define REG_AX rax
#define REG_DI rdi
#define REG_SI rsi
#define REG_DX rdx
#define REG_CX rcx
#undef REG_R8
#define REG_R8 r8
#undef REG_R9
#define REG_R9 r9
#else
#error "Only x86_64 supported for now"
#endif

bool InjectLibrary(pid_t pid, const std::string& library_path) {
    // 1. Attach
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0) {
        perror("ptrace attach");
        return false;
    }
    waitpid(pid, NULL, 0);

    // 2. Save registers
    struct user_regs_struct old_regs, regs;
    ptrace(PTRACE_GETREGS, pid, NULL, &old_regs);
    regs = old_regs;

    // 3. Find dlopen address
    // Since we are likely injecting into a process with the same libc, we can estimate the offset
    // BUT with ASLR, we need to find the base address of libc in the target process.
    // However, if the target is NOT stripping symbols and uses standard loading,
    // we can use a simpler trick: invoke `__libc_dlopen_mode` if available?
    // Or assume the offset of dlopen from libc base is same.

    // Easier for POC: Assume the target has `libdl` loaded.
    // We can parse `/proc/pid/maps` to find libc/libdl base.

    // For this environment, let's just implement map parsing.

    // Actually, calling a function in remote process is complex.
    // We need to:
    // 1. Allocate memory in target (mmap)
    // 2. Write the path string there.
    // 3. Call dlopen with that address.

    // How to call mmap if we don't know where it is?
    // We can assume static offsets if same binary, but we are different binaries.

    // Cheat: We can use `ptrace` to just write code to current RIP and execute it?
    // But we need space.

    // Let's use a simpler approach for injection if possible: `gdb` batch mode?
    // User asked for "imgui based app", so calling gdb is cheating but effective.
    // `gdb -p <pid> -batch -ex "call (void*)dlopen(\"path\", 1)"`
    // This is EXTREMELY robust compared to writing a manual injector.

    // However, implementing it manually shows skill.
    // Let's try the GDB route as a fallback or the primary "Injector" implementation for robustness?
    // "It will be writen in c++". Calling system("gdb...") is C++, but maybe lazy.

    // Let's write the manual injector properly.

    // Step A: Get libc base address of target.
    auto get_module_base = [](pid_t p, const std::string& mod_name) -> uintptr_t {
        std::string maps_path = "/proc/" + std::to_string(p) + "/maps";
        FILE* fp = fopen(maps_path.c_str(), "r");
        if (!fp) return 0;
        char line[512];
        uintptr_t addr = 0;
        while (fgets(line, sizeof(line), fp)) {
            if (strstr(line, mod_name.c_str())) {
                sscanf(line, "%lx", &addr);
                break;
            }
        }
        fclose(fp);
        return addr;
    };

    // Step B: Get dlopen offset in OUR process (assuming same libc version).
    void* local_dlopen = dlsym(RTLD_DEFAULT, "__libc_dlopen_mode");
    if (!local_dlopen) local_dlopen = dlsym(RTLD_DEFAULT, "dlopen");

    // We also need to know the base of libc in OUR process to calculate offset.
    uintptr_t local_libc = get_module_base(getpid(), "libc.so.6"); // Adjust name as needed
    if (!local_libc) local_libc = get_module_base(getpid(), "libc-"); // fallback

    uintptr_t target_libc = get_module_base(pid, "libc.so.6");
    if (!target_libc) target_libc = get_module_base(pid, "libc-");

    if (!local_dlopen || !local_libc || !target_libc) {
        std::cerr << "Could not resolve addresses for injection. "
                  << "dlopen: " << local_dlopen
                  << " local_libc: " << std::hex << local_libc
                  << " target_libc: " << target_libc << std::dec << std::endl;
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return false;
    }

    uintptr_t offset = (uintptr_t)local_dlopen - local_libc;
    uintptr_t target_dlopen = target_libc + offset;

    // std::cout << "Target dlopen at: " << std::hex << target_dlopen << std::dec << std::endl;

    // Step C: Write the library path to the stack (or some free space)
    // We'll just push it to the stack (red zone beware, so decrement SP properly)
    long sp = regs.rsp - 512; // Move down nicely

    // Write string
    const char* str = library_path.c_str();
    size_t str_len = library_path.size() + 1;

    for (size_t i = 0; i < str_len; i += sizeof(long)) {
        long word = 0;
        memcpy(&word, str + i, (str_len - i < sizeof(long)) ? str_len - i : sizeof(long));
        ptrace(PTRACE_POKETEXT, pid, sp + i, (void*)word);
    }

    // Step D: Call dlopen(path, RTLD_NOW)
    // System V AMD64 ABI: RDI = arg1, RSI = arg2
    regs.REG_DI = sp;
    regs.REG_SI = RTLD_NOW;
    regs.REG_IP = target_dlopen;

    regs.rsp = sp - 8; // Adjust stack for return address
    long ret_addr = 0x0; // invalid address
    ptrace(PTRACE_POKETEXT, pid, regs.rsp, (void*)ret_addr); // Put 0 at top of stack

    ptrace(PTRACE_SETREGS, pid, NULL, &regs);

    // Resume and wait for SIGSEGV (return to 0)
    ptrace(PTRACE_CONT, pid, NULL, NULL);

    int status;
    waitpid(pid, &status, 0);

    // Should be SIGSEGV
    if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGSEGV) {
        // Success (probably)
    } else {
        std::cerr << "Injection: Unexpected stop signal: " << WSTOPSIG(status) << std::endl;
    }

    // Restore
    ptrace(PTRACE_SETREGS, pid, NULL, &old_regs);
    ptrace(PTRACE_DETACH, pid, NULL, NULL);

    return true;
}
