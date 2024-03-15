#include "benchmark/benchmark.h"
#include "../src/qclpvss.hpp"
#include <chrono>
#include <cassert>

using namespace benchmark;
using namespace QCLPVSS_;
using namespace BICYCL;
using namespace std;
using namespace std::chrono;

static const Mpz secret(9898UL);
static const int SECLEVEL = 128;
static const size_t N = 10;
static const size_t T = 5;
static const size_t K = 1;
static Mpz Q;
static SecLevel secLevel(SECLEVEL);
static RandGen randgen;
static HashAlgo H(secLevel);
static unique_ptr<QCLPVSS> pvss;

//Global state
static vector<unique_ptr<const SecretKey>> sks(N);
static vector<unique_ptr<const PublicKey>> pks(N);
static vector<unique_ptr<NizkPoK_DL>> keygen_pf(N);
static unique_ptr<vector<unique_ptr<const Share>>> sss_shares;
static unique_ptr<Nizk_SH> sh_pf;
static vector<unique_ptr<const Share>> Ais(N); //on the form <i, Ai>
static vector<unique_ptr<Nizk_DLEQ>> dec_shares(N);

static void setup(benchmark::State& state) {

    auto t = std::chrono::system_clock::now();
    Mpz seed(static_cast<unsigned long>(t.time_since_epoch().count()));
    randgen.set_seed (seed);

    Q = (randgen.random_prime(SECLEVEL + 1));

    for (auto _ : state) {
        pvss = unique_ptr<QCLPVSS>(new QCLPVSS(secLevel, H, randgen, Q, K, N, T, false));
        DoNotOptimize(pvss);
    }

    for(size_t i = 0; i < N; i++) 
    {
        sks[i] = pvss->keyGen(randgen);
        pks[i] = pvss->keyGen(*sks[i]);
        keygen_pf[i] = pvss->keyGen(*pks[i], *sks[i]);
    }

    state.counters["secLevel"] = secLevel.soundness();
}
BENCHMARK(setup)->Unit(kMillisecond);

static void keyGen(benchmark::State& state) {
    for (auto _ : state) {
        unique_ptr<const SecretKey> sk = pvss->keyGen(randgen);
        unique_ptr<const PublicKey> pk = pvss->keyGen(*sk);
        unique_ptr<NizkPoK_DL> pf = pvss->keyGen(*pk, *sk);
        DoNotOptimize(pf);
    }
    state.counters["secLevel"] = secLevel.soundness();
} 
BENCHMARK(keyGen)->Unit(kMillisecond);

static void verifyKey(benchmark::State& state) {
    bool success;
    for (auto _ : state) {
        for(size_t i = 0; i < N; i++)
        {
            success = pvss->verifyKey(*pks[i], *keygen_pf[i]);
            DoNotOptimize(success);
        }
    }
    assert(success);
    state.counters["secLevel"] = secLevel.soundness();
} 
BENCHMARK(verifyKey)->Unit(kMillisecond);

static void dist(benchmark::State& state) {
    for (auto _ : state) {
        sss_shares = pvss->dist(secret);
        sh_pf = pvss->dist(pks, *sss_shares);
        DoNotOptimize(sh_pf);
    }
    state.counters["secLevel"] = secLevel.soundness();
} 
BENCHMARK(dist)->Unit(kMillisecond);


static void verifySharing(benchmark::State& state) {
    bool success;
    for (auto _ : state) {
        success = pvss->verifySharing(pks, *sh_pf);
        DoNotOptimize(success);
    }
    assert(success);
    state.counters["secLevel"] = secLevel.soundness();
} 
BENCHMARK(verifySharing)->Unit(kMillisecond);

//Only one Ai
static void decShare(benchmark::State& state) {
    for (auto _ : state) {
        Ais[0] = pvss->decShare(*sks[0], 0);
        dec_shares[0] = pvss->decShare(*pks[0], *sks[0], 0);
    }

    for(size_t i = 1; i < N; i++)
    {
        Ais[i] = pvss->decShare(*sks[i], i);
        dec_shares[i] = pvss->decShare(*pks[i], *sks[i], i);
    }
    state.counters["secLevel"] = secLevel.soundness();
} 
BENCHMARK(decShare)->Unit(kMillisecond);

static void rec(benchmark::State& state) {
    unique_ptr<const Mpz> s_rec;
    for (auto _ : state) {
        s_rec = pvss->rec(Ais);
        DoNotOptimize(s_rec);
    }

    assert(*s_rec == secret);
    state.counters["secLevel"] = secLevel.soundness();
} 
BENCHMARK(rec)->Unit(kMillisecond);

static void verifyDec(benchmark::State& state) {
    bool success;
    for (auto _ : state) {
        for(size_t i = 0; i < T; i++)
        {
            success = pvss->verifyDec(*Ais[i], *pks[i], *dec_shares[i], i);
            DoNotOptimize(success);
        }
    }
    assert(success);
    state.counters["secLevel"] = secLevel.soundness();
} 
BENCHMARK(verifyDec)->Unit(kMillisecond);

BENCHMARK_MAIN();