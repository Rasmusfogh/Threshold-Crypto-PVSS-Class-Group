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
static const size_t N = 50;
static const size_t T = 25;
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

    // explained in paper that q is twice of seclevel
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

static void keyGen(benchmark::State& state) {
    for (auto _ : state) {
        unique_ptr<const SecretKey> sk = pvss->keyGen(randgen);
        unique_ptr<const PublicKey> pk = pvss->keyGen(*sk);
        unique_ptr<NizkDL> pf = pvss->keyGen(*pk, *sk);
        DoNotOptimize(pf);
    }
    state.counters["secLevel"] = secLevel.soundness();
    state.counters["n"] = N;
    state.counters["t"] = T;
}
BENCHMARK(keyGen)->Unit(kMillisecond);

static void verifyKey(benchmark::State& state) {
    bool success;
    for (auto _ : state) {
        for (size_t i = 0; i < N; i++) {
            success = pvss->verifyKey(*pks[i], *keygen_pf[i]);
            DoNotOptimize(success);
        }
    }
    assert(success);
    state.counters["secLevel"] = secLevel.soundness();
    state.counters["n"] = N;
    state.counters["t"] = T;
}
BENCHMARK(verifyKey)->Unit(kMillisecond);

static void dist(benchmark::State& state) {
    for (auto _ : state) {
        enc_shares = pvss->dist(secret, pks);
        DoNotOptimize(enc_shares);
    }
    state.counters["secLevel"] = secLevel.soundness();
    state.counters["n"] = N;
    state.counters["t"] = T;
}
BENCHMARK(dist)->Unit(kMillisecond);

static void verifySharing(benchmark::State& state) {
    bool success;
    for (auto _ : state) {
        success = pvss->verifySharing(*enc_shares, pks);
        DoNotOptimize(success);
    }
    assert(success);
    state.counters["secLevel"] = secLevel.soundness();
    state.counters["n"] = N;
    state.counters["t"] = T;
}
BENCHMARK(verifySharing)->Unit(kMillisecond);

static void decShare(benchmark::State& state) {
    for (auto _ : state) {
        dec_shares[0] = pvss->decShare(*pks[0], *sks[0], enc_shares->R_,
            *enc_shares->Bs_->at(0), 0);
    }

    for (size_t i = 1; i < N; i++)
        dec_shares[i] = pvss->decShare(*pks[i], *sks[i], enc_shares->R_,
            *enc_shares->Bs_->at(i), i);

    state.counters["secLevel"] = secLevel.soundness();
    state.counters["n"] = N;
    state.counters["t"] = T;
}
BENCHMARK(decShare)->Unit(kMillisecond);

static void rec(benchmark::State& state) {
    unique_ptr<const Mpz> s_rec;

    // Simulate parties reconstructing by providing their share
    for (const auto& dec_share : dec_shares)
        if (dec_share->sh_)
            rec_shares.push_back(
                unique_ptr<const Share>(new Share(*dec_share->sh_)));

    for (auto _ : state) {
        s_rec = pvss->rec(rec_shares);
        DoNotOptimize(s_rec);
    }

    assert(*s_rec == secret);
    state.counters["secLevel"] = secLevel.soundness();
    state.counters["n"] = N;
    state.counters["t"] = T;
}
BENCHMARK(rec)->Unit(kMillisecond);

static void verifyDec(benchmark::State& state) {
    bool success;
    for (auto _ : state) {
        for (size_t i = 0; i < T + 1; i++) {
            success = pvss->verifyDec(*dec_shares[i], *pks[i], enc_shares->R_,
                *enc_shares->Bs_->at(i));
            DoNotOptimize(success);
        }
    }
    assert(success);
    state.counters["secLevel"] = secLevel.soundness();
    state.counters["n"] = N;
    state.counters["t"] = T;
}
BENCHMARK(verifyDec)->Unit(kMillisecond);

BENCHMARK_MAIN();