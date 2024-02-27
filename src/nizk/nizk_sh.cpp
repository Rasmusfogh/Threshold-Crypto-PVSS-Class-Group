#include "nizk_sh.hpp"

using namespace NIZK;

Nizk_SH::Nizk_SH(HashAlgo &hash, RandGen &randgen, const CL_HSMqk &cl_hsm, const SecLevel & seclevel,
    vector<unique_ptr<const PublicKey>>& pks, const vector<unique_ptr<QFI>>& Bs, const QFI& R, 
    const size_t& n, const size_t& t, const Mpz& q, const Mpz& r) : h_(hash), rand_(randgen)
{
    // t = n - t- k - 1, where k = 1
    size_t degree = n - t - 1 - 1;

    //Not sure if correct way to pass f
    initRNG(randgen, pks, Bs, R, cl_hsm.h(), cl_hsm.power_of_f(Mpz(1UL)));

    Mpz vi(1UL);
    Mpz temp;
    Mpz poly_eval(randgen.random_mpz(q)); //first coefficient

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
        Mpz::mul(temp, temp, randgen.random_mpz(q)); //remainging coefficients
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

    pf_ = unique_ptr<Nizk_DLEQ> (new Nizk_DLEQ(hash, randgen, cl_hsm, seclevel, Us, R, Vs, r));
}

bool Nizk_SH::verify(const CL_HSMqk& cl_hsm, vector<unique_ptr<const PublicKey>>& pks, 
    const vector<unique_ptr<QFI>>& Bs, const QFI& R) const
{
    initRNG(rand_, pks, Bs, R, cl_hsm.h(), cl_hsm.power_of_f(Mpz(1UL)));

}

void Nizk_SH::initRNG(RandGen& randgen, vector<unique_ptr<const PublicKey>>& pks, 
    const vector<unique_ptr<QFI>>& Bs, const QFI& R, const QFI&h, const QFI& f) const
{   
    //Calculate seed for the RNG
    const Mpz seed(h_(pks, R, Bs, h, f));
    randgen.set_seed(seed);
}

template<>
void OpenSSL::HashAlgo::hash(const vector<unique_ptr<QFI>> &v)
{
    for(size_t i = 0; i < v.size(); i++)
        hash (*v[i]);
}

template<>
void OpenSSL::HashAlgo::hash(const vector<unique_ptr<const PublicKey>>& v)
{
    for(size_t i = 0; i < v.size(); i++)
        hash (v[i]->get());
}