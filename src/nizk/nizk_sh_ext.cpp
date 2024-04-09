#include "nizk_sh_ext.hpp"

using namespace NIZK;

NizkExtSH::NizkExtSH(HashAlgo& hash, RandGen& rand, const CL_HSMqk& cl,
    const SecLevel& seclevel, const ECGroup& ec_group, const size_t n,
    const size_t t, const Mpz& q, const vector<Mpz>& Vis)
    : BaseNizkSH(hash, rand, cl, seclevel, q, n, t, Vis), ec_group_(ec_group) {

    // Set base class C boundary
    Mpz::mulby2k(this->C_, 1, seclevel.soundness() - 1);
}

void NizkExtSH::prove(const Witness& w,
    const vector<unique_ptr<const PublicKey>>& pks,
    const vector<shared_ptr<QFI>>& Bs, const vector<shared_ptr<ECPoint>>& Ds,
    const QFI& R) {

    pair<const vector<shared_ptr<ECPoint>>&, const ECGroup&> Ds_(Ds, ec_group_);
    init_random_oracle(pks, Bs, Ds_, R, cl_.h());

    vector<Mpz> coeffs;
    coeffs.reserve(t_);
    generateCoefficients(coeffs, t_);

    vector<Mpz> wis;
    wis.reserve(n_);

    for (size_t i = 0; i < n_; i++)
        wis.emplace_back(computeWi(i, coeffs));

    // Verification. If fails, reject
    ECPoint inf(ec_group_), inf_temp(ec_group_);

    for (size_t i = 0; i < n_; i++) {
        ec_group_.scal_mul(inf_temp, BN(wis[i]), *Ds[i]);
        ec_group_.ec_add(inf, inf, inf_temp);
    }

    if (!ec_group_.is_at_infinity(inf))
        throw std::invalid_argument("Failed validating shares");

    QFI U, V;
    computeUVusingWis(U, V, pks, Bs, wis);

    Mpz d(0L), d_temp;
    QFI B, M, temp;
    ECPoint D(ec_group_), D_temp(ec_group_);

    for (size_t i = 0; i < t_; i++) {
        Mpz e(query_random_oracle(q_));

        // compute d
        Mpz::mul(d_temp, e, get<0>(w)[i]->y());
        Mpz::add(d, d, d_temp);

        // compute B
        cl_.Cl_Delta().nupow(temp, *Bs[i], e);
        cl_.Cl_Delta().nucomp(B, B, temp);

        // compute D
        ec_group_.scal_mul(D_temp, BN(e), *Ds[i]);
        ec_group_.ec_add(D, D, D_temp);

        // compute M
        pks[i]->exponentiation(cl_, temp, e);
        cl_.Cl_Delta().nucomp(M, M, temp);
    }

    Mpz::mod(d, d, q_);

    auto witness = tie(get<1>(w), d);

    pf_ = unique_ptr<NizkMixDLEQ>(
        new NizkMixDLEQ(hash_, rand_, cl_, seclevel_, ec_group_));
    pf_->prove(witness, U, M, R, V, B, D);
}

bool NizkExtSH::verify(const vector<unique_ptr<const PublicKey>>& pks,
    const vector<shared_ptr<QFI>>& Bs, const vector<shared_ptr<ECPoint>>& Ds,
    const QFI& R) const {

    pair<const vector<shared_ptr<ECPoint>>&, const ECGroup&> Ds_(Ds, ec_group_);
    init_random_oracle(pks, Bs, Ds_, R, cl_.h());

    vector<Mpz> coeffs;
    coeffs.reserve(t_);
    generateCoefficients(coeffs, t_);

    QFI U, V;
    computeUV(U, V, pks, Bs, coeffs);

    QFI B, M, temp;
    ECPoint D(ec_group_), D_temp(ec_group_);
    for (size_t i = 0; i < t_; i++) {

        Mpz e(query_random_oracle(q_));

        // compute B
        cl_.Cl_Delta().nupow(temp, *Bs[i], e);
        cl_.Cl_Delta().nucomp(B, B, temp);

        // compute D
        ec_group_.scal_mul(D_temp, BN(e), *Ds[i]);
        ec_group_.ec_add(D, D, D_temp);

        // compute M
        pks[i]->exponentiation(cl_, temp, e);
        cl_.Cl_Delta().nucomp(M, M, temp);
    }

    return pf_->verify(U, M, R, V, B, D);
}
