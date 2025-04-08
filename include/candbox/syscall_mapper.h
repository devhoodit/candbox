#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

namespace candbox {

struct Syscall {
    int id;
    std::string name;
    std::string abi;
    bool operator==(const Syscall &other) const {
        return id == other.id && name == other.name && abi == other.abi;
    }
};

class SyscallMapper {
    std::vector<Syscall> _syscalls;
    std::unordered_map<int, std::reference_wrapper<Syscall>> id_map;
    std::unordered_map<std::string, std::reference_wrapper<Syscall>> name_map;

public:
    SyscallMapper(std::vector<Syscall> syscalls);
    void set(const Syscall &pair);
    const Syscall &get(int syscall_num);
    const Syscall &get(std::string syscall_name);

    static std::unique_ptr<SyscallMapper> parseTBLFile(std::string filepath, const std::locale &loc,
                                                       FILE *descriptor = stdout);
};

};  // namespace candbox