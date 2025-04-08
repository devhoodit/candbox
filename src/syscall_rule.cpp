#include <unordered_map>

#include "candbox/candbox.h"

namespace candbox {

const SyscallRule &SandboxRule::get_sysrule(int syscall) const {
    auto rule = syscall_rules.find(syscall);
    if (rule == syscall_rules.end())  // no corresponding rule -> return default rule
    {
        return _default_rule;
    } else {
        return rule->second;
    }
}

};  // namespace candbox