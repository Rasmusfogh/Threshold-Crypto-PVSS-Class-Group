#include "nizk_dleq.hpp"
using namespace NIZK;

Nizk_DLEQ::Nizk_DLEQ(HashAlgo &hash, RandGen &randgen, const CL_HSMqk &cl) 
    : Nizk_base(hash, randgen, cl), C_(cl.encrypt_randomness_bound())
{
    Mpz::mul(A_, cl.encrypt_randomness_bound(), cl.encrypt_randomness_bound());
    Mpz::mul(SC_, cl_.encrypt_randomness_bound(), C_);
    Mpz::add(SC_, A_, SC_);
}

void Nizk_DLEQ::prove(const Mpz& w, const QFI& X1, const QFI& X2, const QFI& Y1, const QFI& Y2)
{
    //u_ = r
    u_ = rand_.random_mpz(A_);

    QFI T1, T2;

    cl_.power_of_h(T1, u_);
    cl_.Cl_Delta().nupow(T2, X2, u_);

    initRandomOracle(X1, X2, Y1, Y2, T1, T2);
    c_ = queryRandomOracle(C_);

    // u_ = r + c_ * w
    Mpz::addmul(u_, c_, w);
}

bool Nizk_DLEQ::verify(const QFI& X1, const QFI& X2, const QFI& Y1, const QFI& Y2) const
{
    if(u_ > SC_)
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
