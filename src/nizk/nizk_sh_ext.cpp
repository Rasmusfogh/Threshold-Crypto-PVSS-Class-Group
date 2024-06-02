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
    generateCoefficients(coeffs);

    QFI U, V;
    computeUV(U, V, pks, Bs, coeffs);

    Mpz d(0L);
    QFI B, M, temp;
    ECPoint D(ec_group_);

    vector<QFI> B_exp(t_);
    vector<QFI> M_exp(t_);

    vector<future<void>> dD_futures;
    vector<future<void>> BM_exp_futures;
    vector<future<void>> BM_futures;

    vector<Mpz> e;
    e.reserve(t_);

    for (size_t i = 0; i < t_; i++)
        e.emplace_back(query_random_oracle(q_));

    // compute d
    dD_futures.emplace_back(pool->enqueue([&]() {
        Mpz d_temp;
        for (size_t i = 0; i < t_; i++) {
            Mpz::mul(d_temp, e[i], get<0>(w)[i]->y());
            Mpz::add(d, d, d_temp);
        }
    }));

    // compute D
    dD_futures.emplace_back(pool->enqueue([&]() {
        ECPoint D_temp(ec_group_);
        for (size_t i = 0; i < t_; i++) {
            ec_group_.scal_mul(D_temp, BN(e[i]), *Ds[i]);
            ec_group_.ec_add(D, D, D_temp);
        }
    }));

    // Compute B and M exponentiations
    for (size_t i = 0; i < t_; i++) {

        BM_exp_futures.emplace_back(pool->enqueue([&, i]() {
            cl_.Cl_Delta().nupow(B_exp[i], *Bs[i], e[i]);
            pks[i]->exponentiation(cl_, M_exp[i], e[i]);
        }));
    }

    for (auto& ft : BM_exp_futures)
        ft.get();

    BM_futures.emplace_back(pool->enqueue([&]() {
        for (size_t i = 0; i < t_; i++)
            cl_.Cl_Delta().nucomp(B, B, B_exp[i]);
    }));

    BM_futures.emplace_back(pool->enqueue([&]() {
        for (size_t i = 0; i < t_; i++)
            cl_.Cl_Delta().nucomp(M, M, M_exp[i]);
    }));

    for (auto& ft : dD_futures)
        ft.get();

    for (auto& ft : BM_futures)
        ft.get();

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
    generateCoefficients(coeffs);

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

    vector<Mpz> e;
    e.reserve(t_);

    for (size_t i = 0; i < t_; i++)
        e.emplace_back(query_random_oracle(q_));

    ECPoint D(ec_group_);
    QFI B, M, temp;
    vector<QFI> B_exp(t_);
    vector<QFI> M_exp(t_);

    vector<future<void>> D_futures;
    vector<future<void>> BM_exp_futures;
    vector<future<void>> BM_futures;

    // compute D
    D_futures.emplace_back(pool->enqueue([&]() {
        ECPoint D_temp(ec_group_);
        for (size_t i = 0; i < t_; i++) {
            ec_group_.scal_mul(D_temp, BN(e[i]), *Ds[i]);
            ec_group_.ec_add(D, D, D_temp);
        }
    }));

    // Compute B and M exponentiations
    for (size_t i = 0; i < t_; i++) {

        BM_exp_futures.emplace_back(pool->enqueue([&, i]() {
            cl_.Cl_Delta().nupow(B_exp[i], *Bs[i], e[i]);
            pks[i]->exponentiation(cl_, M_exp[i], e[i]);
        }));
    }

    for (auto& ft : BM_exp_futures)
        ft.get();

    BM_futures.emplace_back(pool->enqueue([&]() {
        for (size_t i = 0; i < t_; i++)
            cl_.Cl_Delta().nucomp(B, B, B_exp[i]);
    }));

    BM_futures.emplace_back(pool->enqueue([&]() {
        for (size_t i = 0; i < t_; i++)
            cl_.Cl_Delta().nucomp(M, M, M_exp[i]);
    }));

    for (auto& ft : D_futures)
        ft.get();

    for (auto& ft : BM_futures)
        ft.get();

    return pf_->verify(U, M, R, V, B, D);
}
