#include "qclpvss.hpp"
#include <benchmark/benchmark.h>
#include <cassert>

using namespace benchmark;
using namespace QCLPVSS_;

static SecLevel seclevel(128);
static RandGen randgen;
static Mpz q(randgen.random_prime(256));
static HashAlgo H(seclevel);

static size_t n = 10;
static size_t t = 5;
static QCLPVSS pvss(seclevel, H, randgen, q, 1, n, t);

static void nizk_linear_cl(benchmark::State& state) {

    unique_ptr<const SecretKey> sk1 = pvss.keyGen(randgen);
    unique_ptr<const PublicKey> pk1 = pvss.keyGen(*sk1);

    unique_ptr<const SecretKey> sk2 = pvss.keyGen(randgen);
    unique_ptr<const PublicKey> pk2 = pvss.keyGen(*sk2);

    QFI pk12;
    pvss.Cl_Delta().nucomp(pk12, pk1->get(), pk2->get());

    vector<Mpz> w { *sk1, *sk2 };

    vector<vector<QFI>> X { vector<QFI> { pvss.h(), QFI() },
        vector<QFI> { QFI(), pvss.h() }, vector<QFI> { pvss.h(), pvss.h() } };

    vector<QFI> Y { pk1->get(), pk2->get(), pk12 };

    bool verif;
    for (auto _ : state) {
        NizkLinCL uut(H, randgen, pvss, seclevel);

        uut.prove(w, X, Y);
        verif = uut.verify(X, Y);
        DoNotOptimize(verif);
    }

    assert(verif);
}
BENCHMARK(nizk_linear_cl)->Unit(kMillisecond)->Iterations(20);

BENCHMARK_MAIN();