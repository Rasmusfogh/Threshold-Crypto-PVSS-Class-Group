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
static const size_t N = 50;
static const size_t T = 25;
static SecLevel secLevel(SECLEVEL);
static RandGen randgen;
static Mpz Q;
static HashAlgo H(secLevel);
static unique_ptr<PVSS_Reshare> pvss_reshare;

static unique_ptr<vector<EncSharesResh>> enc_sh_resh;

static void setup(benchmark::State& state) {

    auto t = std::chrono::system_clock::now();
    Mpz seed(static_cast<unsigned long>(t.time_since_epoch().count()));
    randgen.set_seed(seed);

    // explained in paper that q is twice of seclevel
    Q = (randgen.random_prime(SECLEVEL * 2));

    for (auto _ : state) {
        pvss_reshare = unique_ptr<PVSS_Reshare>(
            new PVSS_Reshare(secLevel, H, randgen, Q, N, T, N, T));

        pvss_reshare.reset();
        DoNotOptimize(pvss_reshare);
    }

    pvss_reshare = unique_ptr<PVSS_Reshare>(
        new PVSS_Reshare(secLevel, H, randgen, Q, N, T, N, T));

    state.counters["secLevel"] = secLevel.soundness();
    state.counters["n"] = N;
    state.counters["t"] = T;
}
BENCHMARK(setup)->Unit(kMillisecond);

static void reshare(benchmark::State& state) {

    for (auto _ : state) {
        enc_sh_resh = pvss_reshare->reshare(*pvss_reshare->enc_shares);
        DoNotOptimize(enc_sh_resh);
    }

    state.counters["secLevel"] = secLevel.soundness();
    state.counters["n"] = N;
    state.counters["t"] = T;
}
BENCHMARK(reshare)->Unit(kMillisecond);

static void distReshare(benchmark::State& state) {

    for (auto _ : state) {

        assert(pvss_reshare->verifyReshare(*enc_sh_resh,
            *pvss_reshare->enc_shares));

        auto enc_shares = pvss_reshare->distReshare(*enc_sh_resh);
        DoNotOptimize(enc_shares);
    }

    state.counters["secLevel"] = secLevel.soundness();
    state.counters["n"] = N;
    state.counters["t"] = T;
}
BENCHMARK(distReshare)->Unit(kMillisecond);

BENCHMARK_MAIN();