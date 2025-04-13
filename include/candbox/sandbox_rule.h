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

class SandboxRule {
    /**
     * @brief Rules corresponding to syscalls
     * @details The key (int) is syscall and value (SyscallRule) is
     * corresponding rule
     */
    std::unordered_map<int, SyscallRule> syscall_rules;
    SyscallRule _default_rule;

public:
    SandboxRule(std::unordered_map<int, SyscallRule> syscall_rules,
                SyscallRule default_rule = SyscallRule(SyscallRuleType::DISALLOW))
        : syscall_rules(syscall_rules), _default_rule(default_rule) {};
    const SyscallRule &get_sysrule(int syscall) const;
    const std::unordered_map<int, SyscallRule> &get_sysrule_map() const { return syscall_rules; };
    const SyscallRule get_default_rule() const { return _default_rule; }
};

};  // namespace candbox