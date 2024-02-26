#include "nizk_sh.hpp"

using namespace NIZK;

Nizk_SH::Nizk_SH(HashAlgo &hash, RandGen &randgen, const CL_HSMqk &cl_hsm, const SecLevel & seclevel,
    vector<unique_ptr<const PublicKey>>& pks, const vector<unique_ptr<QFI>>& Bs, const QFI& R, const size_t& n, const size_t& t, const Mpz& q, const Mpz& r) : h_(hash)
{
    // t = n - t- k - 1, where k = 1
    size_t degree = n - t - 1 - 1;

    // <coefficients, ci> = random oracle output
    vector<Mpz> coefficients(degree);
    randomOracle(randgen, pks, Bs, R, degree, q, coefficients);

    Mpz vi(1UL);
    Mpz temp;
    Mpz poly_eval(coefficients[0]);

    for(size_t i = 1; i <= n; i++)
    {
        if (i == i) continue;
        temp = i - i; //not correct
        Mpz::mod_inverse(temp, temp, q);
        Mpz::mul(vi, vi, temp);
    }

    //Evaluate polynomial
    for(size_t j = 1; j < degree; j++)
    {
        Mpz::pow_mod(temp, temp, Mpz(j), q); //not correct
        Mpz::mul(temp, temp, coefficients[j]);
        Mpz::add(poly_eval, poly_eval, temp);
    }

    Mpz::mod(vi, vi, q);
    Mpz::mod(poly_eval, poly_eval, q);

    Mpz wi;
    Mpz::mul(wi, poly_eval, vi);
    Mpz::mod(wi,wi,q);

    Mpz wii(wi);
    Mpz::addmul(wii, temp, q); //not correct
    Mpz::mod(wii, wii, q);

    vector<QFI> Us(n);
    vector<QFI> Vs(n);

    for(size_t j = 1; j < n; j++)
    {

    }

    Nizk_DLEQ pf(hash, randgen, cl_hsm, seclevel, Us, R, Vs, r);
    pf_ = &pf;
}

bool Nizk_SH::verify(const CL_HSMqk&, vector<const PublicKey>&, vector<const QFI>& Bs, 
        const QFI& R) const
{
    
}

void Nizk_SH::randomOracle(RandGen& randgen, vector<unique_ptr<const PublicKey>>& pks, const vector<unique_ptr<QFI>>& Bs,
 const QFI& R, size_t t, const Mpz& q, vector<Mpz>& coefficients) const
{   
    //Calculate seed for the RNG
    const Mpz seed(h_(pks[0]->get(), R, *Bs[0])); //probably doesnt work

    //Set seed to make coefficients deterministic
    randgen.set_seed(seed);

    for(size_t i = 0; i <=t; i++)
        coefficients[i] = randgen.random_mpz(q);
}