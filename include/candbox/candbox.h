#pragma once

#include <sys/ptrace.h>

#include <string>
#include <unordered_map>
#include <vector>

#include "sandbox_rule.h"

namespace candbox {

struct ExecConfig {
    char **argv;
    char **envp;
};

struct StackConfig {
    void *stack_pointer;
    size_t stack_size;
};

class Candbox {
public:
    Candbox() = default;
    void execve(ExecConfig const &config, SandboxRule const &SandboxRule, size_t stack_size);

private:
    void execve_child(ExecConfig const &config, SandboxRule const &sandbox_rule,
                      StackConfig const &StackConfig);
    static int clone_child(void *);
    void trace(pid_t pid, SandboxRule const &sandbox_rule, StackConfig const &StackConfig);
};

void trace_syscalls();

};  // namespace candbox