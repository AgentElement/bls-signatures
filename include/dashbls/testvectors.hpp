// Copyright 2022 Blockchain Lab at Arizona State University
// Author: Devansh Patel

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//    http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <cstdint>
#include <filesystem>
#include <iterator>
#include <optional>
#include <util.hpp>
#include <vector>

namespace bls {
class TestVector {
public:
    TestVector(Bytes message, Bytes secret_key, std::optional<Bytes> expected)
        : message(message), secret_key(Bytes(secret_key)), expected(expected){};
    Bytes get_message();
    Bytes get_secret_key();
    std::optional<Bytes> get_expected();

private:
    Bytes message;
    Bytes secret_key;
    std::optional<Bytes> expected;
};

TestVector proc_testvec_line(const std::string& input);

std::vector<TestVector> proc_testvec_file(
    const std::filesystem::path& filename);

std::vector<std::vector<TestVector>> get_default_vecs(
    const std::string& test_type);

}  // namespace bls
