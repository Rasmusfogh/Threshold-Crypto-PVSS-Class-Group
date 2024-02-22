#include "nizk_sh.hpp"

using namespace NIZK;

Nizk_SH::Nizk_SH(HashAlgo &hash, RandGen &randgen, const CL_HSMqk &cl_hsm, const SecLevel & seclevel,
    const PublicKey &pk,const QFI& B, const QFI& R, const size_t n, const size_t t, const Mpz& q, const size_t i) : h_(hash)
{
    // t = n - t- k - 1, where k = 1
    size_t degree = n - t - 1 - 1;

    // <coefficients, ci> = random oracle output
    vector<Mpz> coefficients(degree);
    RandomOracle(randgen, pk, R, B, degree, q, coefficients);

    Mpz vi(1UL);
    Mpz temp;
    Mpz poly_eval(coefficients[0]);
    Mpz ci(i);

    for(size_t j = 1; j <= n; j++)
    {
        if (j == i) continue;
        temp = i - j;
        Mpz::mod_inverse(temp, temp, q);
        Mpz::mul(vi, vi, temp);
    }

    for(size_t j = 1; j < degree; j++)
    {
        Mpz::pow_mod(temp, ci, Mpz(j), q);
        Mpz::mul(temp, temp, coefficients[j]);
        Mpz::add(poly_eval, poly_eval, temp);
    }

    Mpz::mod(vi, vi, q);
    Mpz::mod(poly_eval, poly_eval, q);

    Mpz wi;
    Mpz::mul(wi, poly_eval, vi);
    Mpz::mod(wi,wi,q);

    Mpz wii(wi);
    Mpz::addmul(wii, ci, q);
    Mpz::mod(wii, wii, q);

    Mpz U, V;

    for(size_t j = 1; j < n; j++)
    {

    }
}

void Nizk_SH::RandomOracle(RandGen& randgen, const PublicKey &pk, const QFI& R, 
    const QFI& B, size_t t, const Mpz& q, vector<Mpz>& coefficients) const
{   
    //Calculate seed for the RNG
    const Mpz seed(h_(B.a(), B.b(), B.c(), pk.get().a(), pk.get().b(), pk.get().c()));

    //Set seed to make coefficients deterministic
    randgen.set_seed(seed);

    for(size_t i = 0; i <=t; i++)
        coefficients[i] = randgen.random_mpz(q);
}