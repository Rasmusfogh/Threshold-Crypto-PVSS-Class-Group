#include <iostream>
#include <chrono>
#include <bicycl.hpp>
#include <sss.hpp>
using namespace SSS_;
using namespace BICYCL;

int main (int argc, char *argv[])
{
    Mpz seed;
    RandGen randgen;
    size_t t_ = 300;
    size_t n_ = 500;

    auto T = std::chrono::system_clock::now();
    seed = static_cast<unsigned long>(T.time_since_epoch().count());
    randgen.set_seed (seed);

    Mpz q_(randgen.random_prime(64));
    Mpz s(1234UL);

    std::vector<Share> shares(n_);
    Mpz s_;

    SSS shamir(randgen, t_, n_, q_);
    shamir.shareSecret(s, shares); //figure out how
    shamir.reconstructSecret(shares, s_);

    if (s == s_)
        return EXIT_SUCCESS;

    return EXIT_FAILURE;
}