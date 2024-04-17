#include "nizk_resh.hpp"

using namespace NIZK;

NizkResh::NizkResh(HashAlgo& hash, RandGen& rand, const CL_HSMqk& cl,
    const SecLevel& seclevel, const size_t n, const size_t t, const Mpz& q,
    const vector<Mpz>& Vis)
    : BaseNizkSH(hash, rand, cl, seclevel, q, n, t, Vis) {

    Mpz::mulby2k(this->C_, 1, seclevel.soundness() - 1);
}

void NizkResh::prove(const Witness& w,
    const vector<unique_ptr<const PublicKey>>& pks, const PublicKey& pk_,
    const QFI& R_, const QFI& B_, const QFI& R,
    const vector<shared_ptr<QFI>>& Bs) {

    // Statement values
    QFI U, V, R0, B0;
    computeStatement(U, V, R0, B0, pks, Bs, R, R_, B_);

    QFI VB0;
    cl_.Cl_Delta().nucomp(VB0, V, B0);

    pf_ = unique_ptr<NizkLinCLResh>(
        new NizkLinCLResh(hash_, rand_, cl_, seclevel_));

    // W = (\bar{sk}, r)
    vector<Mpz> W { get<0>(w), get<1>(w) };

    QFI id = cl_.Cl_Delta().one();
    vector<vector<QFI>> X { vector<QFI> { R0, U }, vector<QFI> { cl_.h(), id },
        vector<QFI> { id, cl_.h() } };

    vector<QFI> Y { VB0, pk_.get(), R };

    pf_->prove(W, X, Y);
}

bool NizkResh::verify(const vector<unique_ptr<const PublicKey>>& pks,
    const PublicKey& pk_, const QFI& R_, const QFI& B_, const QFI& R,
    const vector<shared_ptr<QFI>>& Bs) const {

    // Statement values
    QFI U, V, R0, B0;
    computeStatement(U, V, R0, B0, pks, Bs, R, R_, B_);

    QFI id = cl_.Cl_Delta().one();
    vector<vector<QFI>> X { vector<QFI> { R0, U }, vector<QFI> { cl_.h(), id },
        vector<QFI> { id, cl_.h() } };

    QFI VB0;
    cl_.Cl_Delta().nucomp(VB0, V, B0);

    vector<QFI> Y { VB0, pk_.get(), R };

    return pf_->verify(X, Y);
}

void NizkResh::computeStatement(QFI& U, QFI& V, QFI& R0, QFI& B0,
    const vector<unique_ptr<const PublicKey>>& pks,
    const vector<shared_ptr<QFI>>& Bs, const QFI& R, const QFI& R_,
    const QFI& B_) const {

    init_random_oracle(pks, Bs, R, R_, B_, cl_.h());

    vector<Mpz> coeffs;
    generateCoefficients(coeffs);

    vector<Mpz> wis;
    wis.reserve(n_);

    for (size_t i = 0; i < n_; i++)
        wis.emplace_back(computeWi(i + 1, coeffs));

    computeUVusingWis(U, V, pks, Bs, wis);

    Mpz wi0 = computeWi(0, coeffs);

    // compute wi' = wi
    Mpz ci(this->query_random_oracle(C_));
    Mpz::addmul(wi0, ci, q_);

    this->cl_.Cl_Delta().nupow(R0, R_, wi0);
    this->cl_.Cl_Delta().nupow(B0, B_, wi0);
}