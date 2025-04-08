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

class Candbox {
public:
    Candbox() = default;
    void execve(ExecConfig const &config, SandboxRule const &SandboxRule);

private:
    void execve_child(ExecConfig const &config, SandboxRule const &sandbox_rule);
    void trace(pid_t pid, SandboxRule const &sandbox_rule);
};

void trace_syscalls();

};  // namespace candbox