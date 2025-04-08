#include <string>
#include <vector>

std::vector<std::string> split(std::string input, std::string delimiter) {
    std::vector<std::string> tokens;
    size_t pos = 0;
    std::string token;
    size_t delimiter_len = delimiter.length();

    while ((pos = input.find(delimiter)) != std::string::npos) {
        token = input.substr(0, pos);
        tokens.push_back(token);
        input.erase(0, pos + delimiter_len);
    }

    tokens.push_back(token);
    return tokens;
}