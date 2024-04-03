#include "nizk_sh.hpp"

using namespace NIZK;

Nizk_SH::Nizk_SH(HashAlgo& hash, RandGen& randgen, const CL_HSMqk& cl,
    const SecLevel& seclevel, const size_t n, const size_t t, const Mpz& q,
    const vector<Mpz>& Vis)
    : Nizk_SH_base(hash, randgen, cl, seclevel, q, n, t, Vis) {

    // Set base class C boundary
    Mpz::mulby2k(this->C_, 1, seclevel.soundness() - 1);
}

void Nizk_SH::prove(const Mpz& r,
    const vector<unique_ptr<const PublicKey>>& pks,
    const vector<shared_ptr<QFI>>& Bs, const QFI& R) {
    // Not sure if correct way to pass f
    initRandomOracle(pks, Bs, R, cl_.h());

    vector<Mpz> coeffs;
    coeffs.reserve(t_);
    generateCoefficients(coeffs, t_);

    QFI U, V;
    computeUV(U, V, pks, Bs, coeffs);

    // remember to call prove on cl.h(), U, R, V, r
    pf_ = unique_ptr<Nizk_DLEQ>(new Nizk_DLEQ(hash_, rand_, cl_, seclevel_));
    pf_->prove(r, cl_.h(), U, R, V);
}

bool Nizk_SH::verify(const vector<unique_ptr<const PublicKey>>& pks,
    const vector<shared_ptr<QFI>>& Bs, const QFI& R) const {
    initRandomOracle(pks, Bs, R, cl_.h());

    vector<Mpz> coeffs;
    coeffs.reserve(t_);
    generateCoefficients(coeffs, t_);

    QFI U, V;
    computeUV(U, V, pks, Bs, coeffs);

    return pf_->verify(cl_.h(), U, R, V);
}