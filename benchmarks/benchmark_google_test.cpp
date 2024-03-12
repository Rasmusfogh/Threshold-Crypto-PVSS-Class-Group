#include "benchmark/benchmark.h"
#include "../src/qclpvss.hpp"
#include <chrono>

using namespace benchmark;
using namespace QCLPVSS_;
using namespace BICYCL;
using namespace std;
using namespace std::chrono;

static void keyGen(State& state) 
{
    Mpz seed;
    SecLevel seclevel(128);
    size_t k = 1;
    RandGen randgen;

    auto T = system_clock::now();
    seed = static_cast<unsigned long>(T.time_since_epoch().count());
    randgen.set_seed (seed);

    BICYCL::Mpz q(randgen.random_prime(129));

    OpenSSL::HashAlgo H (seclevel);

    size_t n(10UL);
    size_t t(5UL);

    QCLPVSS pvss(seclevel, H, randgen, q, k, n, t, false);


    for(auto _ : state)
    {
        state.counters["secLevel"] = seclevel.soundness();
        unique_ptr<NizkPoK_DL> pf;
        unique_ptr<const SecretKey> sk = pvss.keyGen(randgen);
        unique_ptr<const PublicKey> pk = pvss.keyGen(*sk);
        DoNotOptimize(pf = pvss.keyGen(*pk, *sk));
    }
}

//Pass args for secLevel and n
BENCHMARK(keyGen)->Unit(kMillisecond)->Iterations(20);


BENCHMARK_MAIN();