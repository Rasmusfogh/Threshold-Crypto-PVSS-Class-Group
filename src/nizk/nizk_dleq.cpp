#include "nizk_dleq.hpp"
using namespace NIZK;

Nizk_DLEQ::Nizk_DLEQ(HashAlgo &hash, RandGen &randgen, const CL_HSMqk &cl,
    const QFI& X2, const QFI& Y1, const QFI& Y2, const Mpz& w) : hash_(hash), CL_(cl)
{
    Mpz::mul(A_, cl.encrypt_randomness_bound(), cl.encrypt_randomness_bound());

    Mpz r(randgen.random_mpz(A_));

    QFI T1, T2;

    cl.power_of_h(T1, r);
    cl.Cl_Delta().nupow(T2, X2, r);
    
    //cl.h() = X1 = g_q
    c_ = hash_(cl.h(), X2, Y1, Y2, T1, T2);

    Mpz::mul(u_, c_, w);
    Mpz::add(u_, u_, r);
}

bool Nizk_DLEQ::verify(const QFI& X2, const QFI& Y1, const QFI& Y2) const
{
    //Not sure that this boundary is correctly computed, prob not
    Mpz SC(1UL), boundary(0UL);
    Mpz C(CL_.encrypt_randomness_bound());
    Mpz::mul(SC, CL_.encrypt_randomness_bound(), C);
    Mpz::add(boundary, A_, SC);

    if(u_ > boundary)
        return false;

    QFI T1, T2, temp;

    CL_.power_of_h(T1, u_);
    CL_.Cl_Delta().nupow(temp, Y1, c_);
    CL_.Cl_Delta().nucompinv(T1, T1, temp);

    CL_.Cl_Delta().nupow(T2, X2, u_);
    CL_.Cl_Delta().nupow(temp, Y2, c_);
    CL_.Cl_Delta().nucompinv(T2, T2, temp);

    //CL_.h() = X1 = g_q
    return c_ == Mpz(hash_(CL_.h(), X2, Y1, Y2, T1, T2));
}
