#include "testvectors.hpp"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include "util.hpp"

namespace bls {

Bytes TestVector::get_message() { return message; }
Bytes TestVector::get_secret_key() { return secret_key; }
std::optional<Bytes> TestVector::get_expected() { return expected; }

TestVector proc_testvec_line(const std::string& input)
{
    std::istringstream sstream(input);
    std::vector<Bytes> result;
    for (size_t i = 0; i < 3; ++i) {
        std::string hex;
        if (!std::getline(sstream, hex, ' ')) {
            break;
        }
        if (hex.length() < 64) {
            size_t difference = 64 - std::min((size_t)64, hex.length());
            hex = std::string(difference, '0') + hex;
        }
        result.push_back(Bytes(Util::HexToBytes(hex)));
    }

    std::optional<Bytes> expected = std::nullopt;
    if (result.size() > 2) {
        expected.emplace(result.back());
        result.pop_back();
    }

    Bytes secret_key = result.back();
    result.pop_back();
    Bytes message = result.back();
    result.pop_back();
    return TestVector(message, secret_key, expected);
}

std::vector<TestVector> proc_testvec_file(const std::filesystem::path& filename)
{
    std::ifstream istrm(filename, std::ios::in);
    std::string line;
    std::vector<TestVector> test_vectors;
    while (std::getline(istrm, line)) {
        test_vectors.push_back(proc_testvec_line(line));
    }
    return test_vectors;
}

std::vector<std::vector<TestVector>> get_default_vecs(
    const std::string& test_type)
{
    std::filesystem::path test_path = std::filesystem::current_path()
                                          .append("test-vectors")
                                          .append(test_type);
    std::vector<std::vector<TestVector>> default_vec;
    for (auto const& dir_entry :
         std::filesystem::directory_iterator{test_path}) {
        if (!dir_entry.is_directory()) {
            default_vec.push_back(proc_testvec_file(dir_entry));
        }
    }
    return default_vec;
}

}  // namespace bls
