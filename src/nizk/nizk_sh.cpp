#include "nizk_sh.hpp"

using namespace NIZK;
using namespace UTILS;

NizkSH::NizkSH(HashAlgo& hash, RandGen& randgen, const CL_HSMqk& cl,
    const SecLevel& seclevel, const size_t n, const size_t t, const Mpz& q,
    const vector<Mpz>& Vis)
    : BaseNizkSH(hash, randgen, cl, seclevel, q, n, t, Vis) {

    // Set base class C boundary
    Mpz::mulby2k(this->C_, 1, seclevel.soundness() - 1);
}

void NizkSH::prove(const Mpz& r, const vector<unique_ptr<const PublicKey>>& pks,
    const vector<shared_ptr<QFI>>& Bs, const QFI& R) {

    QFI U, V;
    computeStatement(U, V, pks, Bs, R);

    pf_ = unique_ptr<NizkDLEQ>(new NizkDLEQ(hash_, rand_, cl_, seclevel_));

    vector<Mpz> w { r };
    vector<vector<QFI>> X { vector<QFI> { cl_.h() }, vector<QFI> { U } };
    vector<QFI> Y { R, V };

    pf_->prove(w, X, Y);
}

bool NizkSH::verify(const vector<unique_ptr<const PublicKey>>& pks,
    const vector<shared_ptr<QFI>>& Bs, const QFI& R) const {

    QFI U, V;
    computeStatement(U, V, pks, Bs, R);

    vector<vector<QFI>> X { vector<QFI> { cl_.h() }, vector<QFI> { U } };
    vector<QFI> Y { R, V };

    return pf_->verify(X, Y);
}

void NizkSH::computeStatement(QFI& U, QFI& V,
    const vector<unique_ptr<const PublicKey>>& pks,
    const vector<shared_ptr<QFI>>& Bs, const QFI& R) const {

    init_random_oracle(pks, Bs, R, cl_.h());

    vector<Mpz> coeffs;
    generateCoefficients(coeffs);

    computeUV(U, V, pks, Bs, coeffs);
}