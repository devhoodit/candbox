#include "candbox/candbox.h"

#include <linux/sched.h>
#include <sched.h>
#include <seccomp.h>
#include <string.h>
#include <sys/mman.h>
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

void Candbox::execve(ExecConfig const &config, SandboxRule const &sandbox_rule,
                     size_t stack_size = 1024 * 1024) {
    void *stack = mmap(nullptr, stack_size, PROT_READ | PROT_WRITE | PROT_EXEC,
                       MAP_ANONYMOUS | MAP_SHARED, -1, 0);
    const StackConfig stack_config = {stack, stack_size};
    pid_t pid = fork();
    if (pid == -1) {  // fork fail
        throw std::runtime_error("fork failed");
    }

    if (pid == 0)  // child
    {
        int result = setpgid(0, 0);
        if (result < 0) exit(1);
        execve_child(config, sandbox_rule, stack_config);  // never return;
    }
    return trace(pid, sandbox_rule, stack_config);
}

void Candbox::trace(pid_t delegate_pid, SandboxRule const &sandbox_rule,
                    StackConfig const &stack_config) {
    // this method is core of tracing child process
    // there are two kind of traced processes
    // 1. delegate process
    // 2. child process (what we really want to trace)
    // role of delegate process is setting context of proccess (at this point, the context is not
    // yet applied) and fork process to child inherit and apply the context. After fork child,
    // delegate process must be exited

    // So, our logic resolve this step with very simple steps
    // 1. fork to create delegate process (already done)
    // 2. inject trace context to delegate process
    // 3. delegate process configures additional context ifself (this is system call)
    // step 3 needs system call so, tracer allow all syscalls
    // 4. delegate fork to create child process, child process try execve syscall
    // 5. tracer pass all delegate process fork until delegate is exited and stop child's execve
    // event
    // 6. tracer check delegate process is exited, continue child's exec event and trace all syscall
    // until done
    int status;
    pid_t pid;

    // initialize ptrace option
    // After child ptrace_me, SIGSTOP on child -> parent wait SIGSTOP and set
    // option -> SIGCONT
    pid = waitpid(delegate_pid, &status, WUNTRACED);
    if (pid < 0) {
        return;
    }

    {
        // checkout man page to get option information
        // https://man7.org/linux/man-pages/man2/ptrace.2.html
        auto option = PTRACE_O_EXITKILL | PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXIT |
                      PTRACE_O_TRACEEXEC | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK |
                      PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACESECCOMP;
        long result = ptrace(PTRACE_SETOPTIONS, delegate_pid, NULL, option);
        if (result < 0)  // ptrace set option fail
        {
            kill(delegate_pid, SIGKILL);
            return;
        }
        // set option success, continue
        ptrace(PTRACE_CONT, pid, NULL, NULL);
    }

    // find tracee and allow all ptrace event in delegate process
    // delegate process set configure and clone execve with namespace setting
    // delegate process create child process with clone + CLONE_PARENT so that
    // child process can point parent process to this process
    bool tracee_exists = false;
    pid_t tracee_pid;
    while (true) {
        // only waiting delegate pid
        int signal = 0;
        pid = waitpid(delegate_pid, &status, __WALL);
        if (pid == -1) {
            break;
        }
        if (WSTOPSIG(status) == SIGTRAP) {
            if (status >> 16 == PTRACE_EVENT_CLONE) {
                unsigned long child_pid;
                ptrace(PTRACE_GETEVENTMSG, pid, nullptr, &child_pid);
                tracee_pid = static_cast<int>(child_pid);
                tracee_exists = true;
            }
        }
        ptrace(PTRACE_CONT, pid, NULL, signal);
    }

    if (!tracee_exists) {
        return;
    }

    // allow all syscall and ptrace event until get EVENT_EXEC (EVENT EXEC occur after exec done)
    // this work on single process so wait only tracee first
    bool exec_exists = false;
    while (true) {
        int signal = 0;
        pid = waitpid(tracee_pid, &status, __WALL);
        if (pid == -1) {
            break;
        }
        if (WSTOPSIG(status) == SIGTRAP) {
            if (status >> 16 == PTRACE_EVENT_EXEC) {
                exec_exists = true;
                break;
            }
        }
        ptrace(PTRACE_CONT, pid, NULL, signal);
    }
    if (!exec_exists) {
        return;
    }

    // we suspend PTRACE EVENT EXEC, so cont this event
    ptrace(PTRACE_CONT, tracee_pid, NULL, 0);

    // After exec, free child stack (see, clone stacksize)
    int result = munmap(stack_config.stack_pointer, stack_config.stack_size);
    if (result < 0) {
        return;
    }

    // now we can trace all after execve
    // we want to trace tracee and it's own childs so we trace group pid of tracee
    // NOTE: delegate process already dead here
    pid_t tracee_gpid = -delegate_pid;
    while (true) {
        int signal = 0;
        pid = waitpid(tracee_gpid, &status, __WALL);
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

            bool is_disallow = true;
            const SyscallRule &syscall_rule = sandbox_rule.get_sysrule(syscall_num);
            switch (syscall_rule.type()) {
                case SyscallRuleType::ALLOW:
                    is_disallow = false;
                    break;
                case SyscallRuleType::DISALLOW:
                    break;
                case SyscallRuleType::CALLBACK:
                    is_disallow = syscall_rule.callback(syscall_num);
                    break;
                default:
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
                            break;
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

void Candbox::execve_child(ExecConfig const &config, SandboxRule const &sandbox_rule,
                           StackConfig const &stack_config) {
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

    auto copy = config;
    auto arg = static_cast<void *>(&copy);
    int rc = seccomp_load(ctx);
    if (rc < 0) {
        seccomp_release(ctx);
        exit(1);
    }
    seccomp_release(ctx);

    void *stack_top_pointer = stack_config.stack_pointer + stack_config.stack_size;

    NamespaceRule namespace_rule = sandbox_rule.get_namespace_rule();
    int clone_option = namespace_rule.get_clone_option();
    int pid = clone(Candbox::clone_child, stack_top_pointer, clone_option, arg);
    if (pid < 0) exit(1);
    exit(0);
}

int Candbox::clone_child(void *arg) {
    ExecConfig &config = *static_cast<ExecConfig *>(arg);
    ::execve(config.argv[0], config.argv, config.envp);
    exit(1);
    return 0;
}

int NamespaceRule::get_clone_option() {
    int option = CLONE_PARENT;
    if (new_pid) {
        option |= CLONE_NEWPID;
    }
    if (new_user) {
        option |= CLONE_NEWUSER;
    }
    return option;
};

};  // namespace candbox
