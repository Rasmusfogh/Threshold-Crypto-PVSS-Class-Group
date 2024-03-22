#include <nizk_dleq_mix.hpp>

using namespace NIZK;

Nizk_DLEQ_mix::Nizk_DLEQ_mix(HashAlgo& hash, RandGen& rand, const CL_HSMqk& cl, const Secp256k1& secp256k1)
    : Nizk_base(hash, rand, cl), secp256k1_(secp256k1), C_(cl.encrypt_randomness_bound())
{
    Mpz::mul(A_, cl.encrypt_randomness_bound(), cl.encrypt_randomness_bound());
    //Define A_ and C_
}

void Nizk_DLEQ_mix::prove(const pair<Mpz, Mpz>& w, const QFI& X1, const QFI& X2,
    const QFI& Y1, const QFI& Y2, const QFI& Y3, const Mpz& Y4)
{
    Mpz r = rand_.random_mpz(A_); //TODO: set A_
    Mpz d = rand_.random_mpz(cl_.q());

    QFI R;
    cl_.power_of_h(R, r);

    QFI V;
    cl_.Cl_Delta().nupow(V, X1, r);

    QFI B;
    cl_.Cl_Delta().nupow(B, X2, r);
    QFI fd = cl_.power_of_f(d);
    cl_.Cl_Delta().nucomp(B, B, fd);

    Mpz D = secp256k1_.exponent(d);

    //maybe add g_q, f, h?
    initRandomOracle(X1, X2, Y1, Y2, Y3, Y4, R, V, B, D);
    c_ = queryRandomOracle(C_); //TODO: set C_

    Mpz::mul(ud_, c_, w.second);
    Mpz::add(ud_, ud_, d);
    Mpz::mod(ud_, ud_, cl_.q());

    Mpz::mul(ur_, c_, w.first);
    Mpz::add(ur_, ur_, r);
}

bool Nizk_DLEQ_mix::verify(const QFI& X1, const QFI& X2, const QFI& Y1, 
    const QFI& Y2, const QFI& Y3, const Mpz& Y4) const
{
    QFI R, R_temp;
    cl_.power_of_h(R_temp, ur_);
    cl_.Cl_Delta().nupow(R, Y1, c_);
    cl_.Cl_Delta().nucompinv(R, R_temp, R);

    QFI V, V_temp;
    cl_.Cl_Delta().nupow(V_temp, X1, ur_);
    cl_.Cl_Delta().nupow(V, Y2, c_);
    cl_.Cl_Delta().nucompinv(V, V_temp, V);

    QFI B, B_temp;
    B_temp = cl_.power_of_f(ud_);
    cl_.Cl_Delta().nupow(B, X2, ur_);
    cl_.Cl_Delta().nucomp(B_temp, B_temp, B);
    cl_.Cl_Delta().nupow(B, Y3, c_);
    cl_.Cl_Delta().nucompinv(B, B_temp, B);

    Mpz D, D_temp;
    Mpz c_neg = c_;
    c_neg.neg();
    D_temp = secp256k1_.exponent(ud_);
    Mpz::pow_mod(D, Y4, c_neg, cl_.q());
    Mpz::mul(D, D, D_temp);
    Mpz::mod(D, D, cl_.q());

    initRandomOracle(X1, X2, Y1, Y2, Y3, Y4, R, V, B, D);

    return c_ == queryRandomOracle(C_);
}