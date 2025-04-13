#include "candbox/syscall_mapper.h"

#include <fcntl.h>

#include <algorithm>
#include <codecvt>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

#include "candbox/string_util.h"

namespace candbox {

SyscallMapper::SyscallMapper(std::vector<Syscall> syscalls) {
    _syscalls = syscalls;
    auto pair_iter = _syscalls.begin();
    for (; pair_iter != _syscalls.end(); pair_iter++) {
        auto s_pair = *pair_iter;
        id_map.emplace(s_pair.id, std::ref(*pair_iter));
        name_map.emplace(s_pair.name, std::ref(*pair_iter));
    }
}

void SyscallMapper::set(const Syscall &pair) {
    auto tmp = id_map.find(pair.id);
    size_t idx;
    if (tmp != id_map.end())

    // if id already in syscall pairs
    {
        auto it = std::find_if(_syscalls.begin(), _syscalls.end(),
                               [&pair](const Syscall &p) { return pair.id == p.id; });
        idx = it - _syscalls.begin();
        _syscalls[idx] = pair;
    } else {
        _syscalls.push_back(pair);
        idx = _syscalls.size();
    }

    id_map.emplace(pair.id, std::ref(_syscalls[idx]));
    name_map.emplace(pair.name, std::ref(_syscalls[idx]));
}

std::unique_ptr<SyscallMapper> SyscallMapper::parseTBLFile(std::string filepath,
                                                           const std::locale &loc, FILE *fp) {
    if (fp == nullptr) {
        int fd = open("/dev/null", O_WRONLY);
        if (fd == -1) {
            throw std::runtime_error("no file exits");
        }
        fp = fdopen(fd, "w");
    }

    std::ifstream tbl_file(filepath);
    if (!tbl_file.is_open()) {
        throw std::runtime_error("no file exists");
    }
    tbl_file.imbue(loc);

    std::vector<Syscall> syscall_pairs = {};

    std::string line;
    while (getline(tbl_file, line)) {
        auto cols = split(line, "\t");
        if (cols.size() < 3) {
            fprintf(fp, "unknown col: cannot parse \"%s\"\n", line.c_str());
            continue;
        }

        auto syscall_num_str = cols[0];
        auto syscall_abi = cols[1];
        auto syscall_name = cols[2];
        int syscall_id;
        try {
            syscall_id = std::stoi(syscall_num_str);
        } catch (std::invalid_argument &) {
            fprintf(fp, "unknown col: cannot parse \"%s\"\n", line.c_str());
            continue;
        }

        syscall_pairs.push_back(Syscall{syscall_id, syscall_abi, syscall_name});
    }

    return std::make_unique<SyscallMapper>(syscall_pairs);
}

};  // namespace candbox