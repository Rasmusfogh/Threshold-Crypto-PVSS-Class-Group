#include "nizk_dleq.hpp"
using namespace NIZK;

NizkDLEQ::NizkDLEQ(HashAlgo& hash, RandGen& randgen, const CL_HSMqk& cl,
    const SecLevel& seclevel)
    : BaseLinCL(hash, randgen, cl, seclevel, 1) {}

void NizkDLEQ::prove(const Mpz& w, const QFI& X1, const QFI& X2, const QFI& Y1,
    const QFI& Y2) {

    Mpz r = rand_.random_mpz(A_);

    QFI T1, T2;

    cl_.power_of_h(T1, r);
    cl_.Cl_Delta().nupow(T2, X2, r);

    init_random_oracle(X1, X2, Y1, Y2, T1, T2);
    c_ = query_random_oracle(C_);

    // u_ = r + c_ * w
    Mpz::addmul(r, c_, w);

    u_[0] = r;
}

bool NizkDLEQ::verify(const QFI& X1, const QFI& X2, const QFI& Y1,
    const QFI& Y2) const {

    if (u_[0] > SCA_)
        return false;

    QFI T1, T2, temp;

    cl_.power_of_h(T1, u_[0]);
    cl_.Cl_Delta().nupow(temp, Y1, c_);

    cl_.Cl_Delta().nucompinv(T1, T1, temp);

    cl_.Cl_Delta().nupow(T2, X2, u_[0]);
    cl_.Cl_Delta().nupow(temp, Y2, c_);
    cl_.Cl_Delta().nucompinv(T2, T2, temp);

    init_random_oracle(X1, X2, Y1, Y2, T1, T2);

    // CL_.h() = X1 = g_q
    return c_ == query_random_oracle(C_);
}
