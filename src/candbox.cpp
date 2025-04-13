#include "candbox/candbox.h"

#include <linux/sched.h>
#include <sched.h>
#include <seccomp.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#include <chrono>
#include <iostream>
#include <stdexcept>
#include <string>
#include <thread>
#include <unordered_map>

namespace candbox {

void Candbox::execve(ExecConfig const &config, SandboxRule const &sandbox_rule) {
    pid_t pid = fork();
    if (pid == -1) {  // fork fail
        throw std::runtime_error("fork failed");
    }

    if (pid == 0)  // child
    {
        setpgid(0, 0);
        execve_child(config, sandbox_rule);  // never return;
    }
    trace(pid, sandbox_rule);
}

void Candbox::trace(pid_t tracee_pid, SandboxRule const &sandbox_rule) {
    // checkout man page to get option information
    // https://man7.org/linux/man-pages/man2/ptrace.2.html

    int status;
    pid_t pid;

    // initialize ptrace option
    // After child ptrace_me, SIGSTOP on child -> parent wait SIGSTOP and set
    // option -> SIGCONT
    pid = waitpid(tracee_pid, &status, WUNTRACED);
    if (pid < 0) {
        return;
    }

    auto option = PTRACE_O_EXITKILL | PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXIT |
                  PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACESYSGOOD |
                  PTRACE_O_TRACESECCOMP;
    long result = ptrace(PTRACE_SETOPTIONS, tracee_pid, NULL, option);
    if (result < 0)  // ptrace set option fail
    {
        kill(tracee_pid, SIGKILL);
        return;
    } else  // set option success, continue
    {
        ptrace(PTRACE_CONT, pid, NULL, NULL);
    }

    while (true) {
        int signal = 0;
        pid = waitpid(-tracee_pid, &status, __WALL);
        if (pid == -1) {
            break;
        }

        // exit by exit(0) (normal exit) or exit by signal
        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            if (pid == tracee_pid) {
                break;
            }
        }

        bool is_seccomp_event = status >> 8 == (SIGTRAP | (PTRACE_EVENT_SECCOMP << 8));

        if (is_seccomp_event) {
            __ptrace_syscall_info syscall_info;
            ptrace(PTRACE_GET_SYSCALL_INFO, pid, sizeof(syscall_info), &syscall_info);
            int syscall_num = static_cast<int>(syscall_info.seccomp.nr);

            bool is_disallow = false;
            const SyscallRule &syscall_rule = sandbox_rule.get_sysrule(syscall_num);
            switch (syscall_rule.type()) {
                case SyscallRuleType::ALLOW:
                    break;
                case SyscallRuleType::DISALLOW:
                    is_disallow = true;
                    break;
                case SyscallRuleType::CALLBACK:
                    is_disallow = syscall_rule.callback(syscall_num);
                    break;
                default:
                    is_disallow = true;
                    break;
            }
            if (is_disallow) {
                break;
            }
        } else {
            // other event
            switch (WSTOPSIG(status)) {
                case SIGTRAP:
                    switch (status >> 16) {
                        case (PTRACE_EVENT_EXIT):
                            break;
                        case (PTRACE_EVENT_FORK):
                        case (PTRACE_EVENT_VFORK):
                        case (PTRACE_EVENT_CLONE):
                        case (PTRACE_EVENT_EXEC):
                            break;
                        default:
                            break;
                    }
                    break;
                default:
                    break;
            }
        }

        ptrace(PTRACE_CONT, pid, NULL, signal);
    }
    return;
}

void Candbox::execve_child(ExecConfig const &config, SandboxRule const &sandbox_rule) {
    // fork from Candbox::execv
    if (ptrace(PTRACE_TRACEME, 0, nullptr, nullptr)) {
        perror("tracee | ptrace trace failed");
        exit(1);
    }

    // send event to parent for setting child trace option ->
    raise(SIGSTOP);
    // -> parent setting option and SIGCONT

    // add seccomp rules from config syscall rules
    uint32_t seccomp_init_option;

    // optioni must be SCMP_ACT_TRACE to trace all syscall no matter it it
    // ALLOW, ERRNO if init option is ERRNO, seccomp just return errno to
    // thread so that tracer can't recognize fail and fall into infinite loop
    // about handling segmentfault by ERRNO (I think...) So, MUST check syscall
    // in tracer with default rule !!!
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_TRACE(0));

    // Tracer trace regradless of whether below logic exists or not
    auto rule_map = sandbox_rule.get_sysrule_map();
    for (auto rule_pair : rule_map) {
        int syscall = rule_pair.first;
        SyscallRule rule = rule_pair.second;
        switch (auto i = rule.type()) {
            case SyscallRuleType::ALLOW:
                seccomp_rule_add(ctx, SCMP_ACT_ALLOW, syscall, 0);
                break;
            case SyscallRuleType::CALLBACK:
                seccomp_rule_add(ctx, SCMP_ACT_TRACE(0), syscall, 0);
                break;
            case SyscallRuleType::DISALLOW:
                // ERRNO to ptrace
                seccomp_rule_add(ctx, SCMP_ACT_ERRNO(1), syscall, 0);
                break;
            default:
                break;
        }
    }

    int rc = seccomp_load(ctx);
    if (rc < 0) {
        seccomp_release(ctx);
        exit(1);
    }
    seccomp_release(ctx);

    ::execve(config.argv[0], config.argv, config.envp);
    perror("tracee | execve failed\n");
    exit(1);
}

};  // namespace candbox