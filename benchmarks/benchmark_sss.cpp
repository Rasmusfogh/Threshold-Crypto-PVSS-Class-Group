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
    size_t t_ = 3;
    size_t n_ = 6;

    auto T = std::chrono::system_clock::now();
    seed = static_cast<unsigned long>(T.time_since_epoch().count());

    /* */
    std::cout << "# Using seed = " << seed << std::endl;
    randgen.set_seed (seed);

    Mpz q_(randgen.random_prime(32));
    Mpz s(123UL);

    std::vector<tuple<unsigned long, Mpz>> shares(n_);
    Mpz s_;

    SSS shamir(randgen, t_, n_, q_);
    shamir.shareSecret(s, shares); //figure out how

    std::vector<tuple< unsigned long, Mpz>> ss{shares[1], shares[3], shares[4]};

    shamir.reconstructSecret(ss, s_);

    if (s == s_)
        return 0;

    return 1;
}