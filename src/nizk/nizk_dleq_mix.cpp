#include "nizk_dleq_mix.hpp"

using namespace NIZK;

NizkMixDLEQ::NizkMixDLEQ(HashAlgo& hash, RandGen& rand, const CL_HSMqk& cl,
    const SecLevel& seclevel, const ECGroup& ec_group)
    : BaseNizkLinCL(hash, rand, cl, seclevel), ec_group_(ec_group) {}

void NizkMixDLEQ::prove(const Witness& w, const QFI& U_, const QFI& M_,
    const QFI& R_, const QFI& V_, const QFI& B_, const ECPoint& D_) {
    Mpz r = rand_.random_mpz(A_);
    Mpz d = rand_.random_mpz(cl_.q());

    vector<future<void>> futures;

    QFI R;
    futures.emplace_back(pool->enqueue([&]() { cl_.power_of_h(R, r); }));

    QFI V;
    futures.emplace_back(
        pool->enqueue([&]() { cl_.Cl_Delta().nupow(V, U_, r); }));

    QFI B;
    futures.emplace_back(pool->enqueue([&]() {
        cl_.Cl_Delta().nupow(B, M_, r);
        QFI fd = cl_.power_of_f(d);
        cl_.Cl_Delta().nucomp(B, B, fd);
    }));

    ECPoint D(ec_group_);
    futures.emplace_back(
        pool->enqueue([&]() { ec_group_.scal_mul_gen(D, BN(d)); }));

    for (auto& ft : futures)
        ft.get();

    // maybe add g_q, f, h?
    ECPointGroupCRefPair ecp1(D_, ec_group_);
    ECPointGroupCRefPair ecp2(D, ec_group_);
    init_random_oracle(U_, M_, R_, V_, B_, ecp1, R, V, B, ecp2);

    c_ = query_random_oracle(C_);

    u_.reserve(2);
    u_.emplace_back(d);
    u_.emplace_back(r);

    Mpz::addmul(u_[0], c_, get<1>(w));
    Mpz::mod(u_[0], u_[0], cl_.q());

    Mpz::addmul(u_[1], c_, get<0>(w));
}

bool NizkMixDLEQ::verify(const QFI& U_, const QFI& M_, const QFI& R_,
    const QFI& V_, const QFI& B_, const ECPoint& D_) const {

    vector<future<void>> futures;

    QFI R;
    futures.emplace_back(pool->enqueue([&]() {
        QFI temp;

        cl_.power_of_h(temp, u_[1]);
        cl_.Cl_Delta().nupow(R, R_, c_);
        cl_.Cl_Delta().nucompinv(R, temp, R);
    }));

    QFI V;
    futures.emplace_back(pool->enqueue([&]() {
        QFI temp;

        cl_.Cl_Delta().nupow(temp, U_, u_[1]);
        cl_.Cl_Delta().nupow(V, V_, c_);
        cl_.Cl_Delta().nucompinv(V, temp, V);
    }));

    QFI B;
    futures.emplace_back(pool->enqueue([&]() {
        QFI temp = cl_.power_of_f(u_[0]);
        cl_.Cl_Delta().nupow(B, M_, u_[1]);
        cl_.Cl_Delta().nucomp(temp, temp, B);
        cl_.Cl_Delta().nupow(B, B_, c_);
        cl_.Cl_Delta().nucompinv(B, temp, B);
    }));

    ECPoint D(ec_group_);
    futures.emplace_back(pool->enqueue([&]() {
        ECPoint D_temp(ec_group_);

        ec_group_.scal_mul_gen(D_temp, BN(u_[0]));

        BN c_bn(c_);
        c_bn.neg();

        ec_group_.scal_mul(D, c_bn, D_);
        ec_group_.ec_add(D, D, D_temp);
    }));

    for (auto& ft : futures)
        ft.get();

    ECPointGroupCRefPair ecp1(D_, ec_group_);
    ECPointGroupCRefPair ecp2(D, ec_group_);
    init_random_oracle(U_, M_, R_, V_, B_, ecp1, R, V, B, ecp2);

    Mpz c = query_random_oracle(C_);
    return c_ == c;
}