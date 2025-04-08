# Candbox
C++ sandbox executor library just for fun  
Tracking and blocking system call or computing resource usage of a proccess executed via ```execve```
     
Currently suppport
- Syscall tracking / blocking with execve


# Install
```bash
$ git clone https://github.com/devhoodit/candbox.git
$ cd candbox && mkdir build && cd build
$ cmake .. && cmake --build .
```
Install in include/
```bash
$ sudo cmake --install .
```

# Support platform
| platform | support |
| --- | --- |
| linux x64 | :heavy_check_mark: |

# How to use
- Sandbox: execve with sandbox configure  
- SyscallMapper: Mapping syscalls to names. Parsing from a TBL file  
  
## Sandbox
### Example
```cpp
#include "candbox/canbox.h"

// all candbox object are in namespace
using namespace candbox; 

int main()
{
    // make Candbox object
    Candbox cand;

    // default callback for SyscallRuleType::CALLBACK
    bool (*callback)(int)= [](int syscall) ->bool
    {
        printf("syscall: %d\n", syscall);
        return false;
    };

    // Sandbox syscall default rule type
    SyscallRule default_rule = SyscallRule(SyscallRuleType::CALLBACK, callback);

    // change specific syscall
    std::unordered_map<int, SyscallRule> syscall_rule = {
        {1, SyscallRule(SyscallRuleType::ALLOW)},
    };

    // create Sandbox ruleset with default and specific rules
    SandboxRule sandbox_rule = SandboxRule(syscall_rule, default_rule);

    // execve with sandbox_rule
    char *argv[] = {(char *)"/usr/bin/ls", (char *)"-al", nullptr};
    cand.execve({argv}, sandbox_rule);
}
```

### SyscallRuleType
```cpp
SyscallRuleType::ALLOW;
SyscallRuleType::DISALLOW;
SyscallRuleType::CALLBACK;
```

### SyscallRule
```cpp
// rule allow or disallow
SyscallRule(SyscallRuleType::ALLOW);

// If rule is callback, need callback
// If callback return is true, stop tracing and kill tracee
bool (*callback)(int) = [](int syscall) -> bool { return false; };
SyscallRule(SyscallRuleType::CALLBACK, callback);
```

### SandboxRule
```cpp
// Sandbox syscall default rule type
SyscallRule default_rule = SyscallRule(SyscallRuleType::CALLBACK, callback);

// change specific syscall
// syscall 1 is write in linux_x86-64
std::unordered_map<int, SyscallRule> syscall_rule = {
    {1, SyscallRule(SyscallRuleType::ALLOW)},
};

// create Sandbox ruleset with default and specific rules
SandboxRule sandbox_rule = SandboxRule(syscall_rule, default_rule);
```

### Candbox execve
```cpp
char *argv[] = {(char *)"/usr/bin/ls", (char *)"-al", nullptr};
char *envp[] = {(char *)"KEY=VALUE", nullptr};
ExecConfig exec_config = {argv, envp};
SandboxRule sandbox_rule = ...

candbox.execve(exec_config, sandbox_rule);
```

## SyscallMapper

### Parse TBL from file
TBL file from [linux/arch/x86/entry/syscalls/syscall_xx.tbl](https://github.com/torvalds/linux/tree/master/arch/x86/entry/syscalls)
```cpp
#include <candbox/syscall_mapper.h>

using namespace candbox;

std::locale loc = std::locale(std::locale(), new std::codecvt_utf8<wchar_t>);
std::unique_ptr<SyscallMapper> mapper = SyscallMapper::parseTBLFile("tbl/syscall_64.tbl", loc, nullptr);
```