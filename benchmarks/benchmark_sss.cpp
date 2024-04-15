#include "qclpvss.hpp"
#include <benchmark/benchmark.h>
#include <bicycl.hpp>
#include <chrono>
#include <iostream>
#include <sss.hpp>

using namespace benchmark;
using namespace QCLPVSS_;
using namespace BICYCL;
using namespace std;
using namespace std::chrono;

static const size_t N = 500;
static const size_t T = 250;
static Mpz Q;
static RandGen randgen;
static unique_ptr<SSS> sss;
static const Mpz secret(1234UL);

// Global state
static unique_ptr<vector<unique_ptr<const Share>>> shares;
static unique_ptr<const Mpz> s_;

static void setup(benchmark::State& state) {
    Mpz seed;
    auto t = std::chrono::system_clock::now();
    seed = static_cast<unsigned long>(t.time_since_epoch().count());
    randgen.set_seed(seed);

    Q = (randgen.random_prime(128));

    for (auto _ : state) {
        sss = unique_ptr<SSS>(new SSS(randgen));
    }
}
BENCHMARK(setup)->Unit(kMillisecond);

static void share(benchmark::State& state) {
    for (auto _ : state) {
        shares = sss->shareSecret(secret, T, N, Q);
        DoNotOptimize(shares);
    }
}
BENCHMARK(share)->Unit(kMillisecond);

static void reconstruct(benchmark::State& state) {
    unique_ptr<const Mpz> s_;
    for (auto _ : state) {
        s_ = sss->reconstructSecret(*shares, T + 1, Q);
        DoNotOptimize(s_);
    }
    assert(*s_ == secret);
}
BENCHMARK(reconstruct)->Unit(kMillisecond);

BENCHMARK_MAIN();