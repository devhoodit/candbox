#include <concepts>
#include <stdexcept>
#include <unordered_map>

namespace candbox {

enum SyscallRuleType { ALLOW, CALLBACK, DISALLOW };

class SyscallRule {
    SyscallRuleType _type;

public:
    bool (*callback)(int);
    SyscallRule(SyscallRuleType type, bool (*callback)(int) = nullptr)
        : _type(type), callback(callback) {
        if (type == SyscallRuleType::CALLBACK && callback == nullptr) {
            throw std::invalid_argument(
                "ruletype is callback so expect callback function but callback "
                "is null");
        }
    };
    const SyscallRuleType type() const { return _type; }
};

class NamespaceRule {
    bool new_pid;
    bool new_user;

public:
    NamespaceRule(bool new_pid, bool new_user) : new_pid(new_pid), new_user(new_user) {}
    int get_clone_option();
};

class SandboxRule {
    /**
     * @brief Rules corresponding to syscalls
     * @details The key (int) is syscall and value (SyscallRule) is
     * corresponding rule
     */
    std::unordered_map<int, SyscallRule> syscall_rules;
    SyscallRule _default_syscall_rule;
    NamespaceRule _namespace_rule;

public:
    SandboxRule(std::unordered_map<int, SyscallRule> syscall_rules,
                SyscallRule default_rule = SyscallRule(SyscallRuleType::DISALLOW),
                NamespaceRule namespace_rule = NamespaceRule(false, false))
        : syscall_rules(syscall_rules),
          _default_syscall_rule(default_rule),
          _namespace_rule(namespace_rule) {};
    const SyscallRule &get_sysrule(int syscall) const;
    const std::unordered_map<int, SyscallRule> &get_sysrule_map() const { return syscall_rules; };
    const SyscallRule get_default_syscall_rule() const { return _default_syscall_rule; }
    const NamespaceRule get_namespace_rule() const { return _namespace_rule; }
};

};  // namespace candbox