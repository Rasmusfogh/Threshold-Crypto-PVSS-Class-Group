#include "bdkg.hpp"
#include <benchmark/benchmark.h>
#include <chrono>

using namespace benchmark;
using namespace QCLPVSS_;
using namespace Application;

static const int SECLEVEL = 128;
static const size_t N = 50;
static const size_t T = 25;
static const size_t K = 1;
static SecLevel secLevel(SECLEVEL);
static ECGroup ec_group_(secLevel);
static Mpz Q(ec_group_.order());
static RandGen randgen;
static HashAlgo H(secLevel);
static unique_ptr<BDKG> bdkg;

// Global state
static vector<unique_ptr<EncSharesExt>> enc_sh(T + 1);

static vector<vector<shared_ptr<QFI>>> Bs_transpose;
static vector<QFI> Rs_transpose;

static vector<Mpz> tsks;
static vector<ECPoint> tpks;

static void setup(benchmark::State& state) {

    tsks.reserve(T + 1);
    tpks.reserve(T + 1);
    generate_n(back_inserter(tpks), T + 1, [&] { return ECPoint(ec_group_); });

    auto t = chrono::system_clock::now();
    Mpz seed(static_cast<unsigned long>(t.time_since_epoch().count()));
    randgen.set_seed(seed);

    bool success;
    for (auto _ : state) {
        bdkg = unique_ptr<BDKG>(
            new BDKG(secLevel, H, randgen, ec_group_, Q, K, N, T));
    }

    state.counters["secLevel"] = secLevel.soundness();
    state.counters["n"] = N;
    state.counters["t"] = T;
}
BENCHMARK(setup)->Unit(kMillisecond);

static void dist(benchmark::State& state) {

    for (auto _ : state) {
        for (size_t j = 0; j < T + 1; j++) {

            Mpz s_j = (randgen.random_mpz(Q));
            enc_sh[j] = bdkg->dist(s_j, bdkg->pks_);
        }
    }

    state.counters["secLevel"] = secLevel.soundness();
    state.counters["n"] = N;
    state.counters["t"] = T;
}
BENCHMARK(dist)->Unit(kMillisecond)->Iterations(1);

static void compute_threshold_keypair(benchmark::State& state) {

    Bs_transpose.reserve(T + 1);
    Rs_transpose.reserve(T + 1);

    // Simulate sharing of Bs and Rs between parties
    for (size_t i = 0; i < T + 1; i++) {
        Bs_transpose.emplace_back(vector<shared_ptr<QFI>>());
        Bs_transpose[i].reserve(T + 1);

        for (size_t j = 0; j < T + 1; j++)
            Bs_transpose[i].emplace_back(enc_sh[j]->Bs_->at(i));
    }

    for (size_t i = 0; i < T + 1; i++)
        Rs_transpose.emplace_back(enc_sh[i]->R_);

    bool success;
    for (auto _ : state) {

        for (size_t j = 0; j < T; j++) {
            success = enc_sh[j]->pf_->verify(bdkg->pks_, *enc_sh[j]->Bs_,
                *enc_sh[j]->Ds_, enc_sh[j]->R_);
        }

        for (size_t i = 0; i < T + 1; i++) {
            for (size_t j = 0; j < T + 1; j++)
                ec_group_.ec_add(tpks[i], tpks[i], *enc_sh[j]->Ds_->at(i));
        }

        unique_ptr<ECPoint> tpk = move(bdkg->compute_tpk(tpks));

        Mpz tsk_i =
            bdkg->compute_tsk_i(Bs_transpose[0], Rs_transpose, *bdkg->sks_[0]);
    }
    assert(success);
    state.counters["secLevel"] = secLevel.soundness();
    state.counters["n"] = N;
    state.counters["t"] = T;
}
BENCHMARK(compute_threshold_keypair)->Unit(kMillisecond)->Iterations(1);

BENCHMARK_MAIN();