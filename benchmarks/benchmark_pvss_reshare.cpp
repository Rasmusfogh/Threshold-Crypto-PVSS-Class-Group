#include "pvss_reshare.hpp"
#include <benchmark/benchmark.h>
#include <cassert>
#include <chrono>

using namespace benchmark;
using namespace QCLPVSS_;
using namespace Application;

static const int SECLEVEL = 128;
static const size_t N = 900;
static const size_t T = 450;
static SecLevel secLevel(SECLEVEL);
static RandGen randgen;
static HashAlgo H(secLevel);
static ECGroup ec_group_(secLevel);
static Mpz Q(ec_group_.order());
static unique_ptr<PVSS_Reshare> pvss_reshare;

static unique_ptr<vector<EncSharesResh>> enc_sh_resh;

static void setup(benchmark::State& state) {

    auto t = std::chrono::system_clock::now();
    Mpz seed(static_cast<unsigned long>(t.time_since_epoch().count()));
    randgen.set_seed(seed);

    for (auto _ : state) {
        pvss_reshare = unique_ptr<PVSS_Reshare>(
            new PVSS_Reshare(secLevel, H, randgen, Q, N, T, N, T));
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
    }

    state.counters["secLevel"] = secLevel.soundness();
    state.counters["n"] = N;
    state.counters["t"] = T;
}
BENCHMARK(reshare)->Unit(kMillisecond);

static void rec(benchmark::State& state) {

    for (auto _ : state) {

        assert(pvss_reshare->verifyReshare(*enc_sh_resh,
            *pvss_reshare->enc_shares));

        auto enc_shares = pvss_reshare->distReshare(*enc_sh_resh);
    }

    state.counters["secLevel"] = secLevel.soundness();
    state.counters["n"] = N;
    state.counters["t"] = T;
}
BENCHMARK(rec)->Unit(kMillisecond);

BENCHMARK_MAIN();