#include "nizk_resh.hpp"

using namespace NIZK;

NizkResh::NizkResh(HashAlgo& hash, RandGen& rand, const CL_HSMqk& cl,
    const SecLevel& seclevel, const size_t n, const size_t t, const Mpz& q,
    const vector<Mpz>& Vis)
    : BaseNizkSH(hash, rand, cl, seclevel, q, n, t, Vis) {

    Mpz::mulby2k(this->C_, 1, seclevel.soundness() - 1);
}

void NizkResh::prove(const tuple<Mpz, Mpz, vector<unique_ptr<const Share>>&>& w,
    const vector<unique_ptr<const PublicKey>>& pks, const PublicKey& pk_,
    const QFI& R_, const QFI& B_, const QFI& R,
    const vector<shared_ptr<QFI>>& Bs) {

    init_random_oracle(pks, Bs, R, cl_.h());

    vector<Mpz> coeffs;
    coeffs.reserve(t_);
    generateCoefficients(coeffs, t_);

    vector<Mpz> wis;
    wis.reserve(n_);

    for (size_t i = 0; i < n_; i++)
        wis.emplace_back(computeWi(i, coeffs));

    QFI U, V;
    computeUVusingWis(U, V, pks, Bs, wis);

    Mpz w_0, temp;
    Mpz ci(this->query_random_oracle(C_));
    Mpz::mul(temp, ci, q_);
    Mpz::add(temp, wis[0], temp);

    QFI R0;
    this->cl_.Cl_Delta().nupow(R0, R_, w_0);

    QFI B0;
    this->cl_.Cl_Delta().nupow(B0, B_, w_0);
}

bool NizkResh::verify(const vector<unique_ptr<const PublicKey>>& pks,
    const PublicKey& pk_, const QFI& R_, const QFI& B_, const QFI& R,
    const vector<shared_ptr<QFI>>& Bs) const {}