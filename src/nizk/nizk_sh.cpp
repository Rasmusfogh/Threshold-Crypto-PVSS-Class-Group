#include "nizk_sh.hpp"

using namespace NIZK;

Nizk_SH::Nizk_SH(HashAlgo &hash, RandGen &randgen, const CL_HSMqk &cl,
    vector<unique_ptr<const PublicKey>>& pks, const vector<QFI>& Bs, const QFI& R, const Mpz& r,
    const size_t& n, const size_t& t, const Mpz& q, const vector<unique_ptr<Mpz>>& Vis) 
    : Nizk_SH_base(hash, randgen, cl, q, n, t, Vis)
{
    //Not sure if correct way to pass f
    initRandomOracle(pks, Bs, R, cl.h(), cl.power_of_f(Mpz(1UL)));

    vector<Mpz> coeffs(t);
    generateCoefficients(coeffs);

    QFI U, V;
    computeUV(U, V, pks, Bs, coeffs);

    pf_ = unique_ptr<Nizk_DLEQ> (new Nizk_DLEQ(hash, randgen, cl, cl.h(), U, R, V, r));
}

bool Nizk_SH::verify(const vector<unique_ptr<const PublicKey>>& pks, const vector<QFI>& Bs, 
    const QFI& R) const
{
    initRandomOracle(pks, Bs, R, cl_.h(), cl_.power_of_f(Mpz(1UL)));

    vector<Mpz> coeffs(t_);
    generateCoefficients(coeffs);

    QFI U, V;
    computeUV(U, V, pks, Bs, coeffs);

    return pf_->verify(cl_.h(), U, R, V);
}