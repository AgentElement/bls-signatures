// Copyright 2022 Blockchain Lab at Arizona State University

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//    http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.


#define CATCH_CONFIG_RUNNER
#include <thread>
#include <catch2/catch.hpp>

#include <chrono>
#include <cstdint>

#include "bls.hpp"
#include "elements.hpp"
#include "privatekey.hpp"
#include "schemes.hpp"
#include "testvectors.hpp"



namespace bls {
#define BLS_BENCH_NITER 1000

std::chrono::nanoseconds bench_sign_basic(const std::vector<TestVector>& tests)
{
    std::chrono::nanoseconds vector_test_time =
        std::chrono::nanoseconds::zero();
    for (TestVector testvec : tests) {
        Bytes secret_key = testvec.get_secret_key();
        Bytes message = testvec.get_message();
        Bytes expect = testvec.get_expected().value();

        BasicSchemeMPL scheme = BasicSchemeMPL();
        PrivateKey scheme_sk = scheme.KeyGen(secret_key);
        G1Element pubkey = scheme_sk.GetG1Element();

        auto start = std::chrono::steady_clock::now();
        G2Element signature = scheme.Sign(scheme_sk, message);
        auto end = std::chrono::steady_clock::now();

        auto time = (end - start);
        vector_test_time += time;
    }
    return vector_test_time;
}

std::chrono::nanoseconds bench_verify_basic(
    const std::vector<TestVector>& tests)
{
    std::chrono::nanoseconds vector_test_time =
        std::chrono::nanoseconds::zero();
    for (TestVector testvec : tests) {
        Bytes secret_key = testvec.get_secret_key();
        Bytes message = testvec.get_message();
        Bytes expect = testvec.get_expected().value();

        BasicSchemeMPL scheme = BasicSchemeMPL();
        PrivateKey scheme_sk = scheme.KeyGen(secret_key);
        G1Element pubkey = scheme_sk.GetG1Element();
        G2Element signature = scheme.Sign(scheme_sk, message);

        auto start = std::chrono::steady_clock::now();
        bool verified = scheme.Verify(pubkey, message, signature);
        auto end = std::chrono::steady_clock::now();

        auto time = (end - start);
        vector_test_time += time;
    }
    return vector_test_time;
}

std::chrono::nanoseconds bench_aggregate_basic(
    const std::vector<TestVector>& tests)
{
    std::chrono::nanoseconds vector_test_time =
        std::chrono::nanoseconds::zero();
    std::vector<G2Element> signatures;
    BasicSchemeMPL scheme = BasicSchemeMPL();
    for (TestVector testvec : tests) {
        Bytes secret_key = testvec.get_secret_key();
        Bytes message = testvec.get_message();
        Bytes expect = testvec.get_expected().value();

        PrivateKey scheme_sk = scheme.KeyGen(secret_key);
        G1Element pubkey = scheme_sk.GetG1Element();
        G2Element signature = scheme.Sign(scheme_sk, message);
        signatures.push_back(signature);
    }

    auto start = std::chrono::steady_clock::now();
    G2Element aggsig = scheme.Aggregate(signatures);
    auto end = std::chrono::steady_clock::now();

    auto time = (end - start);
    vector_test_time += time;
    return vector_test_time;
}

std::chrono::nanoseconds bench_aggregate_verify_basic(
    const std::vector<TestVector>& tests)
{
    std::chrono::nanoseconds vector_test_time =
        std::chrono::nanoseconds::zero();
    std::vector<G2Element> signatures;
    std::vector<G1Element> publickeys;
    std::vector<Bytes> messages;
    BasicSchemeMPL scheme = BasicSchemeMPL();
    for (TestVector testvec : tests) {
        Bytes secret_key = testvec.get_secret_key();
        Bytes message = testvec.get_message();
        Bytes expect = testvec.get_expected().value();

        PrivateKey scheme_sk = scheme.KeyGen(secret_key);
        G1Element pubkey = scheme_sk.GetG1Element();
        G2Element signature = scheme.Sign(scheme_sk, message);

        signatures.push_back(signature);
        messages.push_back(message);
        publickeys.push_back(pubkey);
    }

    G2Element aggsig = scheme.Aggregate(signatures);
    auto start = std::chrono::steady_clock::now();
    bool verified = scheme.AggregateVerify(publickeys, messages, aggsig);
    auto end = std::chrono::steady_clock::now();

    auto time = (end - start);
    vector_test_time += time;
    return vector_test_time;
}

std::chrono::nanoseconds bench_sign_aug(const std::vector<TestVector>& tests)
{
    std::chrono::nanoseconds vector_test_time =
        std::chrono::nanoseconds::zero();
    AugSchemeMPL scheme = AugSchemeMPL();
    for (TestVector testvec : tests) {
        Bytes secret_key = testvec.get_secret_key();
        Bytes message = testvec.get_message();
        Bytes expect = testvec.get_expected().value();

        PrivateKey scheme_sk = scheme.KeyGen(secret_key);
        G1Element pubkey = scheme_sk.GetG1Element();

        auto start = std::chrono::steady_clock::now();
        G2Element signature = scheme.Sign(scheme_sk, message);
        auto end = std::chrono::steady_clock::now();

        auto time = (end - start);
        vector_test_time += time;
    }
    return vector_test_time;
}

std::chrono::nanoseconds bench_prepend_aug(const std::vector<TestVector>& tests)
{
    std::chrono::nanoseconds vector_test_time =
        std::chrono::nanoseconds::zero();
    AugSchemeMPL scheme = AugSchemeMPL();
    G1Element prepend_pk;
    bool first = true;
    for (TestVector testvec : tests) {
        Bytes secret_key = testvec.get_secret_key();
        Bytes message = testvec.get_message();
        Bytes expect = testvec.get_expected().value();

        PrivateKey scheme_sk = scheme.KeyGen(secret_key);
        G1Element pubkey = scheme_sk.GetG1Element();

        if (first) {
            first = false;
            prepend_pk = pubkey;
            G2Element signature = scheme.Sign(scheme_sk, message);
            continue;
        }

        auto start = std::chrono::steady_clock::now();
        G2Element signature = scheme.Sign(scheme_sk, message, prepend_pk);
        auto end = std::chrono::steady_clock::now();

        auto time = (end - start);
        vector_test_time += time;
    }
    return vector_test_time;
}

std::chrono::nanoseconds bench_verify_aug(const std::vector<TestVector>& tests)
{
    std::chrono::nanoseconds vector_test_time =
        std::chrono::nanoseconds::zero();
    AugSchemeMPL scheme = AugSchemeMPL();
    G1Element prepend_pk;
    bool first = true;
    for (TestVector testvec : tests) {
        Bytes secret_key = testvec.get_secret_key();
        Bytes message = testvec.get_message();
        Bytes expect = testvec.get_expected().value();

        PrivateKey scheme_sk = scheme.KeyGen(secret_key);
        G1Element pubkey = scheme_sk.GetG1Element();

        if (first) {
            first = false;
            prepend_pk = pubkey;
            G2Element signature = scheme.Sign(scheme_sk, message);
            continue;
        }

        G2Element signature = scheme.Sign(scheme_sk, message, prepend_pk);
        auto start = std::chrono::steady_clock::now();
        bool verified = scheme.Verify(pubkey, message, signature);
        auto end = std::chrono::steady_clock::now();

        auto time = (end - start);
        vector_test_time += time;
    }
    return vector_test_time;
}


std::chrono::nanoseconds bench_aggregate_aug(
    const std::vector<TestVector>& tests)
{
    std::chrono::nanoseconds vector_test_time =
        std::chrono::nanoseconds::zero();
    std::vector<G2Element> signatures;
    AugSchemeMPL scheme = AugSchemeMPL();
    for (TestVector testvec : tests) {
        Bytes secret_key = testvec.get_secret_key();
        Bytes message = testvec.get_message();
        Bytes expect = testvec.get_expected().value();

        PrivateKey scheme_sk = scheme.KeyGen(secret_key);
        G1Element pubkey = scheme_sk.GetG1Element();
        G2Element signature = scheme.Sign(scheme_sk, message);
        signatures.push_back(signature);
    }

    auto start = std::chrono::steady_clock::now();
    G2Element aggsig = scheme.Aggregate(signatures);
    auto end = std::chrono::steady_clock::now();

    auto time = (end - start);
    vector_test_time += time;

    return vector_test_time;
}

std::chrono::nanoseconds bench_aggregate_verify_aug(
    const std::vector<TestVector>& tests)
{
    std::chrono::nanoseconds vector_test_time =
        std::chrono::nanoseconds::zero();
    std::vector<G2Element> signatures;
    std::vector<G1Element> publickeys;
    std::vector<Bytes> messages;
    AugSchemeMPL scheme = AugSchemeMPL();
    for (TestVector testvec : tests) {
        Bytes secret_key = testvec.get_secret_key();
        Bytes message = testvec.get_message();
        Bytes expect = testvec.get_expected().value();

        PrivateKey scheme_sk = scheme.KeyGen(secret_key);
        G1Element pubkey = scheme_sk.GetG1Element();
        G2Element signature = scheme.Sign(scheme_sk, message);

        signatures.push_back(signature);
        messages.push_back(message);
        publickeys.push_back(pubkey);
    }

    G2Element aggsig = scheme.Aggregate(signatures);
    auto start = std::chrono::steady_clock::now();
    bool verified = scheme.AggregateVerify(publickeys, messages, aggsig);
    auto end = std::chrono::steady_clock::now();

    auto time = (end - start);
    vector_test_time += time;

    return vector_test_time;
}

std::chrono::nanoseconds bench_sign_pop(const std::vector<TestVector>& tests)
{
    std::chrono::nanoseconds vector_test_time =
        std::chrono::nanoseconds::zero();
    PopSchemeMPL scheme = PopSchemeMPL();
    for (TestVector testvec : tests) {
        Bytes secret_key = testvec.get_secret_key();
        Bytes message = testvec.get_message();
        Bytes expect = testvec.get_expected().value();

        PrivateKey scheme_sk = scheme.KeyGen(secret_key);
        G1Element pubkey = scheme_sk.GetG1Element();

        auto start = std::chrono::steady_clock::now();
        G2Element proof = scheme.Sign(scheme_sk, message);
        auto end = std::chrono::steady_clock::now();

        auto time = (end - start);
        vector_test_time += time;
    }
    return vector_test_time;
}


std::chrono::nanoseconds bench_verify_pop(const std::vector<TestVector>& tests)
{
    std::chrono::nanoseconds vector_test_time =
        std::chrono::nanoseconds::zero();
    PopSchemeMPL scheme = PopSchemeMPL();
    G1Element prepend_pk;
    bool first = true;
    for (TestVector testvec : tests) {
        Bytes secret_key = testvec.get_secret_key();
        Bytes message = testvec.get_message();
        Bytes expect = testvec.get_expected().value();

        PrivateKey scheme_sk = scheme.KeyGen(secret_key);
        G1Element pubkey = scheme_sk.GetG1Element();

        if (first) {
            first = false;
            prepend_pk = pubkey;
            G2Element signature = scheme.Sign(scheme_sk, message);
            continue;
        }

        G2Element signature = scheme.Sign(scheme_sk, message);
        auto start = std::chrono::steady_clock::now();
        bool verified = scheme.Verify(pubkey, message, signature);
        auto end = std::chrono::steady_clock::now();

        auto time = (end - start);
        vector_test_time += time;
    }
    return vector_test_time;
}


std::chrono::nanoseconds bench_prove_pop(const std::vector<TestVector>& tests)
{
    std::chrono::nanoseconds vector_test_time =
        std::chrono::nanoseconds::zero();
    PopSchemeMPL scheme = PopSchemeMPL();
    for (TestVector testvec : tests) {
        Bytes secret_key = testvec.get_secret_key();
        Bytes message = testvec.get_message();
        Bytes expect = testvec.get_expected().value();

        PrivateKey scheme_sk = scheme.KeyGen(secret_key);
        G1Element pubkey = scheme_sk.GetG1Element();
        G2Element sig = scheme.Sign(scheme_sk, message);

        auto start = std::chrono::steady_clock::now();
        G2Element proof = scheme.PopProve(scheme_sk);
        auto end = std::chrono::steady_clock::now();

        auto time = (end - start);
        vector_test_time += time;
    }
    return vector_test_time;
}



std::chrono::nanoseconds bench_proof_verify_pop(const std::vector<TestVector>& tests)
{
    std::chrono::nanoseconds vector_test_time =
        std::chrono::nanoseconds::zero();
    PopSchemeMPL scheme = PopSchemeMPL();
    for (TestVector testvec : tests) {
        Bytes secret_key = testvec.get_secret_key();
        Bytes message = testvec.get_message();
        Bytes expect = testvec.get_expected().value();

        PrivateKey scheme_sk = scheme.KeyGen(secret_key);
        G1Element pubkey = scheme_sk.GetG1Element();
        G2Element sig = scheme.Sign(scheme_sk, message);
        G2Element proof = scheme.PopProve(scheme_sk);

        auto start = std::chrono::steady_clock::now();
        bool verified = scheme.PopVerify(pubkey, proof);
        auto end = std::chrono::steady_clock::now();

        auto time = (end - start);
        vector_test_time += time;
    }
    return vector_test_time;
}

std::chrono::nanoseconds bench_aggregate_pop(
    const std::vector<TestVector>& tests)
{
    std::chrono::nanoseconds vector_test_time =
        std::chrono::nanoseconds::zero();
    std::vector<G2Element> signatures;
    PopSchemeMPL scheme = PopSchemeMPL();
    for (TestVector testvec : tests) {
        Bytes secret_key = testvec.get_secret_key();
        Bytes message = testvec.get_message();
        Bytes expect = testvec.get_expected().value();

        PrivateKey scheme_sk = scheme.KeyGen(secret_key);
        G1Element pubkey = scheme_sk.GetG1Element();
        G2Element signature = scheme.Sign(scheme_sk, message);
        signatures.push_back(signature);
    }

    auto start = std::chrono::steady_clock::now();
    G2Element aggsig = scheme.Aggregate(signatures);
    auto end = std::chrono::steady_clock::now();

    auto time = (end - start);
    vector_test_time += time;

    return vector_test_time;
}



std::chrono::nanoseconds bench_aggregate_verify_pop(
    const std::vector<TestVector>& tests)
{
    std::chrono::nanoseconds vector_test_time =
        std::chrono::nanoseconds::zero();
    PopSchemeMPL scheme = PopSchemeMPL();

    std::vector<G2Element> signatures;
    std::vector<G1Element> publickeys;
    std::vector<Bytes> messages;

    for (TestVector testvec : tests) {
        Bytes secret_key = testvec.get_secret_key();
        Bytes message = testvec.get_message();
        Bytes expect = testvec.get_expected().value();

        PrivateKey scheme_sk = scheme.KeyGen(secret_key);
        G1Element pubkey = scheme_sk.GetG1Element();
        G2Element sig = scheme.Sign(scheme_sk, message);
        G2Element proof = scheme.PopProve(scheme_sk);

        signatures.push_back(sig);
        publickeys.push_back(pubkey);
        messages.push_back(message);
    }

    auto aggsig = scheme.Aggregate(signatures);

    auto start = std::chrono::steady_clock::now();
    bool verified = scheme.AggregateVerify(publickeys, messages, aggsig);
    auto end = std::chrono::steady_clock::now();

    auto time = (end - start);
    vector_test_time += time;
    return vector_test_time;
}

std::chrono::nanoseconds bench_fast_aggregate_verify_pop(
    const std::vector<TestVector>& tests)
{
    std::chrono::nanoseconds vector_test_time =
        std::chrono::nanoseconds::zero();
    PopSchemeMPL scheme = PopSchemeMPL();

    std::vector<G2Element> signatures;
    std::vector<G1Element> publickeys;

    // Hello, careful wanderer. This is the sixth taxicab number.
    Bytes message =
        std::vector<uint8_t>{24, 15, 33, 19, 58, 12, 54, 31, 20, 65, 34, 4};

    for (TestVector testvec : tests) {
        Bytes secret_key = testvec.get_secret_key();
        Bytes expect = testvec.get_expected().value();

        PrivateKey scheme_sk = scheme.KeyGen(secret_key);
        G1Element pubkey = scheme_sk.GetG1Element();
        G2Element sig = scheme.Sign(scheme_sk, message);
        G2Element proof = scheme.PopProve(scheme_sk);

        signatures.push_back(sig);
        publickeys.push_back(pubkey);
    }

    auto aggsig = scheme.Aggregate(signatures);

    auto start = std::chrono::steady_clock::now();
    bool verified = scheme.FastAggregateVerify(publickeys, message, aggsig);
    auto end = std::chrono::steady_clock::now();

    auto time = (end - start);
    vector_test_time += time;

    return vector_test_time;
}

void bench_g1()
{
    auto sig_basic = get_default_vecs("sig_g2_basic");
    auto sig_aug = get_default_vecs("sig_g2_aug");
    auto sig_pop = get_default_vecs("sig_g2_pop");

    auto dur = std::chrono::nanoseconds::zero();
    size_t ntests = 0;
    for (auto tests : sig_basic) {
        dur += bench_sign_basic(tests);
        ntests += tests.size();
    }
    auto true_dur = (double)dur.count() / ((double)ntests * 1e6);
    std::cout << "[1] Basic scheme signing time (ms): " << true_dur
              << std::endl;

    dur = std::chrono::nanoseconds::zero();
    ntests = 0;
    for (auto tests : sig_basic) {
        dur += bench_verify_basic(tests);
        ntests += tests.size();
    }
    true_dur = (double)dur.count() / ((double)ntests * 1e6);
    std::cout << "[2] Basic scheme verification time (ms): " << true_dur
              << std::endl;

    dur = std::chrono::nanoseconds::zero();
    for (auto tests : sig_basic) {
        dur += bench_aggregate_basic(tests);
    }
    true_dur = (double)dur.count() / ((double)sig_basic.size() * 1e6);
    std::cout << "[3] Basic scheme aggregation time (ms): " << true_dur
              << std::endl;

    dur = std::chrono::nanoseconds::zero();
    for (auto tests : sig_basic) {
        dur += bench_aggregate_verify_basic(tests);
    }
    true_dur = (double)dur.count() / ((double)sig_basic.size() * 1e6);
    std::cout << "[4] Basic scheme aggregate verification time (ms): "
              << true_dur << std::endl;

    dur = std::chrono::nanoseconds::zero();
    ntests = 0;
    for (auto tests : sig_aug) {
        dur += bench_sign_aug(tests);
        ntests += tests.size();
    }
    true_dur = (double)dur.count() / ((double)ntests * 1e6);
    std::cout << "[5] Augment scheme signing time (ms): " << true_dur
              << std::endl;

    dur = std::chrono::nanoseconds::zero();
    ntests = 0;
    for (auto tests : sig_aug) {
        dur += bench_prepend_aug(tests);
        ntests += tests.size() - 1;
    }
    true_dur = (double)dur.count() / ((double)ntests * 1e6);
    std::cout << "[6] Augment scheme prepend time (ms): " << true_dur
              << std::endl;

    dur = std::chrono::nanoseconds::zero();
    ntests = 0;
    for (auto tests : sig_aug) {
        dur += bench_verify_aug(tests);
        ntests += tests.size() - 1;
    }
    true_dur = (double)dur.count() / ((double)ntests * 1e6);
    std::cout << "[7] Augment scheme verification time (ms): " << true_dur
              << std::endl;
    
    dur = std::chrono::nanoseconds::zero();
    for (auto tests : sig_aug) {
        dur += bench_aggregate_aug(tests);
    }
    true_dur = (double)dur.count() / ((double)sig_basic.size() * 1e6);
    std::cout << "[8] Augment scheme aggregation time (ms): " << true_dur
              << std::endl;

    dur = std::chrono::nanoseconds::zero();
    for (auto tests : sig_aug) {
        dur += bench_aggregate_verify_aug(tests);
    }
    true_dur = (double)dur.count() / ((double)sig_basic.size() * 1e6);
    std::cout << "[9] Augment scheme aggregate verification time (ms): "
              << true_dur << std::endl;

    dur = std::chrono::nanoseconds::zero();
    ntests = 0;
    for (auto tests : sig_pop) {
        dur += bench_sign_pop(tests);
        ntests += tests.size();
    }
    true_dur = (double)dur.count() / ((double)ntests * 1e6);
    std::cout << "[10] PoP scheme signing time (ms): " << true_dur << std::endl;

    dur = std::chrono::nanoseconds::zero();
    ntests = 0;
    for (auto tests : sig_pop) {
        dur += bench_verify_pop(tests);
        ntests += tests.size() - 1;
    }
    true_dur = (double)dur.count() / ((double)ntests * 1e6);
    std::cout << "[12] Pop scheme verification time (ms): " << true_dur
              << std::endl;

    dur = std::chrono::nanoseconds::zero();
    ntests = 0;
    for (auto tests : sig_pop) {
        dur += bench_prove_pop(tests);
        ntests += tests.size();
    }
    true_dur = (double)dur.count() / ((double)ntests * 1e6);
    std::cout << "[13] PoP scheme proof time (ms): " << true_dur << std::endl;

    dur = std::chrono::nanoseconds::zero();
    ntests = 0;
    for (auto tests : sig_pop) {
        dur += bench_proof_verify_pop(tests);
        ntests += tests.size();
    }
    true_dur = (double)dur.count() / ((double)ntests * 1e6);
    std::cout << "[13] PoP scheme proof verification time (ms): " << true_dur
              << std::endl;

    dur = std::chrono::nanoseconds::zero();
    for (auto tests : sig_pop) {
        dur += bench_aggregate_pop(tests);
    }
    true_dur = (double)dur.count() / ((double)sig_basic.size() * 1e6);
    std::cout << "[19] Pop scheme aggregation time (ms): " << true_dur
              << std::endl;

    dur = std::chrono::nanoseconds::zero();
    for (auto tests : sig_pop) {
        dur += bench_aggregate_verify_pop(tests);
    }
    true_dur = (double)dur.count() / ((double)sig_pop.size() * 1e6);
    std::cout << "[14] PoP scheme aggregate verification time (ms): "
              << true_dur << std::endl;

    dur = std::chrono::nanoseconds::zero();
    for (auto tests : sig_pop) {
        dur += bench_fast_aggregate_verify_pop(tests);
    }
    true_dur = (double)dur.count() / ((double)sig_pop.size() * 1e6);
    std::cout << "[15] PoP scheme fast aggregate verification time (ms): "
              << true_dur << std::endl;
}
}  // namespace bls
   //
   //
int main(int argc, char* argv[])
{
    bls::bench_g1();
    return 1;
}
