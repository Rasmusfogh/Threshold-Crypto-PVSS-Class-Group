#include "../src/qclpvss.hpp"
#include "benchmark/benchmark.h"
#include <bdkg.hpp>
#include <cassert>
#include <chrono>

using namespace benchmark;
using namespace QCLPVSS_;
using namespace BICYCL;
using namespace std;
using namespace std::chrono;
using namespace Application;

static const int SECLEVEL = 128;
static const size_t N = 100;
static const size_t T = 50;
static const size_t K = 1;
static SecLevel secLevel(SECLEVEL);
static ECGroup ec_group_(secLevel);
static Mpz Q(ec_group_.order());
static RandGen randgen;
static HashAlgo H(secLevel);
static unique_ptr<BDKG> bdkg;

// Global state
static vector<unique_ptr<const SecretKey>> sks(N);
static vector<unique_ptr<const PublicKey>> pks(N);
static vector<unique_ptr<NizkDL>> keygen_pf(N);
static vector<unique_ptr<EncSharesExt>> enc_sh(N);

static vector<vector<shared_ptr<QFI>>> shared_Bs;
static vector<QFI> shared_Rs;

static vector<Mpz> tsks;
static vector<ECPoint> tpks;

static void setup(benchmark::State& state) {

    tsks.reserve(N);
    tpks.reserve(N);
    generate_n(back_inserter(tpks), N, [&] { return ECPoint(ec_group_); });

    auto t = std::chrono::system_clock::now();
    Mpz seed(static_cast<unsigned long>(t.time_since_epoch().count()));
    randgen.set_seed(seed);

    bool success;
    for (auto _ : state) {
        bdkg = unique_ptr<BDKG>(
            new BDKG(secLevel, H, randgen, ec_group_, Q, K, N, T));

        for (size_t i = 0; i < N; i++) {
            sks[i] = bdkg->keyGen(randgen);
            pks[i] = bdkg->keyGen(*sks[i]);
            keygen_pf[i] = bdkg->keyGen(*pks[i], *sks[i]);
            success = bdkg->verifyKey(*pks[i], *keygen_pf[i]);
            assert(success);
        }
    }

    state.counters["secLevel"] = secLevel.soundness();
    state.counters["n"] = N;
    state.counters["t"] = T;
}
BENCHMARK(setup)->Unit(kMillisecond);

static void dist(benchmark::State& state) {

    for (auto _ : state) {
        for (size_t j = 0; j < N; j++) {

            Mpz s_j = (randgen.random_mpz(Q));
            enc_sh[j] = bdkg->dist(s_j, pks);
        }
    }

    state.counters["secLevel"] = secLevel.soundness();
    state.counters["n"] = N;
    state.counters["t"] = T;
}
BENCHMARK(dist)->Unit(kMillisecond)->Iterations(1);

static void compute_threshold_keypair(benchmark::State& state) {

    shared_Bs.reserve(N);
    shared_Rs.reserve(N);

    // Simulate sharing of Bs and Rs between parties
    for (size_t i = 0; i < N; i++) {
        shared_Bs.emplace_back(vector<shared_ptr<QFI>>());
        shared_Bs[i].reserve(N);

        shared_Rs.emplace_back(enc_sh[i]->R_);

        for (size_t j = 0; j < N; j++)
            shared_Bs[i].emplace_back(enc_sh[j]->Bs_->at(i));
    }

    size_t Q = N;

    bool success;
    for (auto _ : state) {

        for (size_t j = 0; j < N; j++) {
            success = enc_sh[j]->pf_->verify(pks, *enc_sh[j]->Bs_,
                *enc_sh[j]->Ds_, enc_sh[j]->R_);
        }

        for (size_t i = 0; i < N; i++) {
            for (size_t j = 0; j < Q; j++)
                ec_group_.ec_add(tpks[i], tpks[i], *enc_sh[j]->Ds_->at(i));
        }

        unique_ptr<ECPoint> tpk = move(bdkg->compute_tpk(tpks));
        DoNotOptimize(tpk);

        Mpz tsk_i = bdkg->compute_tsk_i(shared_Bs[0], shared_Rs, *sks[0]);
        DoNotOptimize(tsk_i);
    }
    assert(success);
    state.counters["secLevel"] = secLevel.soundness();
    state.counters["n"] = N;
    state.counters["t"] = T;
}
BENCHMARK(compute_threshold_keypair)->Unit(kMillisecond);

BENCHMARK_MAIN();