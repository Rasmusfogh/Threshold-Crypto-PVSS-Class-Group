#include <nizk_dleq_mix.hpp>

using namespace NIZK;

Nizk_DLEQ_mix::Nizk_DLEQ_mix(HashAlgo& hash, RandGen& rand, const CL_HSMqk& cl,
    const ECGroup& ec_group)
    : C_(cl.encrypt_randomness_bound()), Nizk_base(hash, rand, cl),
      ec_group_(ec_group) {
    Mpz::mul(A_, cl.encrypt_randomness_bound(), cl.encrypt_randomness_bound());
    // Define A_ and C_
}

void Nizk_DLEQ_mix::prove(const pair<Mpz, Mpz>& w, const QFI& U_, const QFI& M_,
    const QFI& R_, const QFI& V_, const QFI& B_, const ECPoint& D_) {
    Mpz r = rand_.random_mpz(A_);
    Mpz d = rand_.random_mpz(cl_.q());

    QFI R;
    cl_.power_of_h(R, r);

    QFI V;
    cl_.Cl_Delta().nupow(V, U_, r);    // witness or random r?

    QFI B;
    cl_.Cl_Delta().nupow(B, M_, r);
    QFI fd = cl_.power_of_f(d);
    cl_.Cl_Delta().nucomp(B, B, fd);

    ECPoint D(ec_group_);
    ec_group_.scal_mul_gen(D, BN(d));

    // maybe add g_q, f, h?
    ECPointGroupCRefPair ecp1(D_, ec_group_);
    ECPointGroupCRefPair ecp2(D, ec_group_);
    initRandomOracle(U_, M_, R_, V_, B_, ecp1, R, V, B, ecp2);

    c_ = queryRandomOracle(C_);

    Mpz::mul(ud_, c_, w.second);
    Mpz::add(ud_, ud_, d);
    Mpz::mod(ud_, ud_, cl_.q());

    Mpz::mul(ur_, c_, w.first);
    Mpz::add(ur_, ur_, r);
}

bool Nizk_DLEQ_mix::verify(const QFI& U_, const QFI& M_, const QFI& R_,
    const QFI& V_, const QFI& B_, const ECPoint& D_) const {
    QFI temp;

    QFI R;
    cl_.power_of_h(temp, ur_);
    cl_.Cl_Delta().nupow(R, R_, c_);
    cl_.Cl_Delta().nucompinv(R, temp, R);

    QFI V;
    cl_.Cl_Delta().nupow(temp, U_, ur_);
    cl_.Cl_Delta().nupow(V, V_, c_);
    cl_.Cl_Delta().nucompinv(V, temp, V);

    QFI B;
    temp = cl_.power_of_f(ud_);
    cl_.Cl_Delta().nupow(B, M_, ur_);
    cl_.Cl_Delta().nucomp(temp, temp, B);
    cl_.Cl_Delta().nupow(B, B_, c_);
    cl_.Cl_Delta().nucompinv(B, temp, B);

    ECPoint D(ec_group_), D_temp(ec_group_);
    ec_group_.scal_mul_gen(D_temp, BN(ud_));

    BN c_bn(c_);
    c_bn.neg();

    ec_group_.scal_mul(D, c_bn, D_);
    ec_group_.ec_add(D, D, D_temp);

    ECPointGroupCRefPair ecp1(D_, ec_group_);
    ECPointGroupCRefPair ecp2(D, ec_group_);
    initRandomOracle(U_, M_, R_, V_, B_, ecp1, R, V, B, ecp2);

    Mpz c = queryRandomOracle(C_);
    return c_ == c;
}