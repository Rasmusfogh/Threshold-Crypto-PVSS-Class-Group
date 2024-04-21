#include "qclpvss.hpp"
#include <benchmark/benchmark.h>
#include <cassert>
#include <chrono>

using namespace benchmark;
using namespace QCLPVSS_;
using namespace BICYCL;
using namespace std;
using namespace std::chrono;

static const Mpz secret(9898UL);
static const int SECLEVEL = 128;
static const size_t N = 200;
static const size_t T = 100;
static const size_t K = 1;
static Mpz Q;
static SecLevel secLevel(SECLEVEL);
static RandGen randgen;
static HashAlgo H(secLevel);
static unique_ptr<QCLPVSS> pvss;

// Global state
static vector<unique_ptr<const SecretKey>> sks(N);
static vector<unique_ptr<const PublicKey>> pks(N);
static vector<unique_ptr<NizkDL>> keygen_pf(N);
static unique_ptr<EncShares> enc_shares;
static vector<unique_ptr<DecShare>> dec_shares(N);
static vector<unique_ptr<const Share>> rec_shares;

static void setup(benchmark::State& state) {

    auto t = std::chrono::system_clock::now();
    Mpz seed(static_cast<unsigned long>(t.time_since_epoch().count()));
    randgen.set_seed(seed);

    Q = (randgen.random_prime(SECLEVEL * 2));

    for (auto _ : state) {
        pvss =
            unique_ptr<QCLPVSS>(new QCLPVSS(secLevel, H, randgen, Q, K, N, T));
        DoNotOptimize(pvss);
    }

    for (size_t i = 0; i < N; i++) {
        sks[i] = pvss->keyGen(randgen);
        pks[i] = pvss->keyGen(*sks[i]);
        keygen_pf[i] = pvss->keyGen(*pks[i], *sks[i]);
    }

    state.counters["secLevel"] = secLevel.soundness();
    state.counters["n"] = N;
    state.counters["t"] = T;
}
BENCHMARK(setup)->Unit(kMillisecond);

static void deal(benchmark::State& state) {
    for (auto _ : state) {
        enc_shares = pvss->dist(secret, pks);
        DoNotOptimize(enc_shares);
    }
    state.counters["secLevel"] = secLevel.soundness();
    state.counters["n"] = N;
    state.counters["t"] = T;
}
BENCHMARK(deal)->Unit(kMillisecond);

static void recieve(benchmark::State& state) {
    bool success;
    for (auto _ : state) {
        success = pvss->verifySharing(*enc_shares, pks);
        DoNotOptimize(success);

        DoNotOptimize(pvss->decShare(*pks[0], *sks[0], enc_shares->R_,
            *enc_shares->Bs_->at(0), 0));
    }
    assert(success);
    state.counters["secLevel"] = secLevel.soundness();
    state.counters["n"] = N;
    state.counters["t"] = T;
}
BENCHMARK(recieve)->Unit(kMillisecond);

BENCHMARK_MAIN();