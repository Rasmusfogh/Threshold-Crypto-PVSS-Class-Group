#include "pvss_reshare.hpp"
#include "qclpvss.hpp"
#include <benchmark/benchmark.h>
#include <cassert>
#include <chrono>

using namespace benchmark;
using namespace QCLPVSS_;
using namespace BICYCL;
using namespace std;
using namespace std::chrono;
using namespace Application;

static const int SECLEVEL = 128;
static const size_t N = 10;
static const size_t T = 5;
static SecLevel secLevel(SECLEVEL);
static RandGen randgen;
static Mpz Q;    // SET Q!
static HashAlgo H(secLevel);
static unique_ptr<PVSS_Reshare> pvss_reshare;

static void setup(benchmark::State& state) {

    auto t = std::chrono::system_clock::now();
    Mpz seed(static_cast<unsigned long>(t.time_since_epoch().count()));
    randgen.set_seed(seed);

    // explained in paper that q is twice of seclevel
    Q = (randgen.random_prime(SECLEVEL * 2));

    for (auto _ : state) {
        pvss_reshare = unique_ptr<PVSS_Reshare>(
            new PVSS_Reshare(secLevel, H, randgen, Q, N, T));

        pvss_reshare.reset();
        DoNotOptimize(pvss_reshare);
    }

    pvss_reshare = unique_ptr<PVSS_Reshare>(
        new PVSS_Reshare(secLevel, H, randgen, Q, N, T));

    state.counters["secLevel"] = secLevel.soundness();
    state.counters["n"] = N;
    state.counters["t"] = T;
}
BENCHMARK(setup)->Unit(kMillisecond);

static void reshare(benchmark::State& state) {

    for (auto _ : state) {
        auto enc_sh_resh =
            pvss_reshare->reshare(*pvss_reshare->enc_shares, N, T);

        DoNotOptimize(enc_sh_resh);
    }

    state.counters["secLevel"] = secLevel.soundness();
    state.counters["n"] = N;
    state.counters["t"] = T;
}
BENCHMARK(reshare)->Unit(kMillisecond);

BENCHMARK_MAIN();