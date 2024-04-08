#include "sss.hpp"
#include <bicycl.hpp>
#include <chrono>
#include <iostream>
using namespace SSS_;
using namespace BICYCL;

int main(int argc, char* argv[]) {
    Mpz q(5000UL);
    Mpz seed1(5UL);
    Mpz seed2(5UL);
    RandGen randgen1, randgen2;

    randgen1.set_seed(seed1);
    randgen2.set_seed(seed2);

    for (size_t i = 0; i < 100; i++) {
        Mpz rand1(randgen1.random_mpz(q));
        Mpz rand2(randgen2.random_mpz(q));

        if (rand1 != rand2)
            return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}