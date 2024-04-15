#include "sss.hpp"
#include <bicycl.hpp>
#include <chrono>
#include <iostream>
using namespace SSS_;
using namespace BICYCL;

int main(int argc, char* argv[]) {
    Mpz seed;
    RandGen randgen;
    size_t t_ = 5;
    size_t n_ = 10;

    auto T = std::chrono::system_clock::now();
    seed = static_cast<unsigned long>(T.time_since_epoch().count());
    randgen.set_seed(seed);

    Mpz q_(randgen.random_prime(129));
    Mpz s(1234UL);

    unique_ptr<vector<unique_ptr<const Share>>> shares;
    unique_ptr<const Mpz> s_;

    SSS shamir(randgen);
    shares = shamir.shareSecret(s, t_, n_, q_);    // figure out how
    s_ = shamir.reconstructSecret(*shares, t_ + 1, q_);

    if (s == *s_)
        return EXIT_SUCCESS;

    return EXIT_FAILURE;
}