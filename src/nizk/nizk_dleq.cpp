#include "nizk_dleq.hpp"
using namespace NIZK;

Nizk_DLEQ::Nizk_DLEQ(HashAlgo &hash, RandGen &randgen, const CL_HSMqk &cl,
    const QFI& X1, const QFI& X2, const QFI& Y1, const QFI& Y2, const Mpz& w) 
    : C_(cl_.encrypt_randomness_bound()), Nizk_base(hash, randgen, cl)
{
    Mpz::mul(A_, cl.encrypt_randomness_bound(), cl.encrypt_randomness_bound());

    //u_ = r
    u_ = randgen.random_mpz(A_);

    QFI T1, T2;

    cl.power_of_h(T1, u_);
    cl.Cl_Delta().nupow(T2, X2, u_);

    initRandomOracle(X1, X2, Y1, Y2, T1, T2);
    c_ = queryRandomOracle(C_);

    // u_ = r + c_ * w
    Mpz::addmul(u_, c_, w);
}

bool Nizk_DLEQ::verify(const QFI& X1, const QFI& X2, const QFI& Y1, const QFI& Y2) const
{
    //Not sure that this boundary is correctly computed, prob not
    Mpz SC(1UL), boundary(0UL);
    Mpz::mul(SC, cl_.encrypt_randomness_bound(), C_);
    Mpz::add(boundary, A_, SC);

    if(u_ > boundary)
        return false;

    QFI T1, T2, temp;

    cl_.power_of_h(T1, u_);
    cl_.Cl_Delta().nupow(temp, Y1, c_);
    cl_.Cl_Delta().nucompinv(T1, T1, temp);

    cl_.Cl_Delta().nupow(T2, X2, u_);
    cl_.Cl_Delta().nupow(temp, Y2, c_);
    cl_.Cl_Delta().nucompinv(T2, T2, temp);

    initRandomOracle(X1, X2, Y1, Y2, T1, T2);

    //CL_.h() = X1 = g_q
    return c_ == queryRandomOracle(C_);
}
