#include "nizk_dleq.hpp"
using namespace NIZK;

NizkDLEQ::NizkDLEQ(HashAlgo& hash, RandGen& randgen, const CL_HSMqk& cl,
    const SecLevel& seclevel)
    : BaseNizkDLEQ(hash, randgen, cl, seclevel) {}

void NizkDLEQ::prove(const Mpz& w, const QFI& X1, const QFI& X2, const QFI& Y1,
    const QFI& Y2) {
    // u_ = r
    u_ = rand_.random_mpz(A_);

    QFI T1, T2;

    cl_.power_of_h(T1, u_);
    cl_.Cl_Delta().nupow(T2, X2, u_);

    init_random_oracle(X1, X2, Y1, Y2, T1, T2);
    c_ = query_random_oracle(C_);

    // u_ = r + c_ * w
    Mpz::addmul(u_, c_, w);
}

bool NizkDLEQ::verify(const QFI& X1, const QFI& X2, const QFI& Y1,
    const QFI& Y2) const {

    Mpz SCA_;
    Mpz::mul(SCA_, S_, C_);
    Mpz::add(SCA_, SCA_, A_);

    if (u_ > SCA_)
        return false;

    QFI T1, T2, temp;

    cl_.power_of_h(T1, u_);
    cl_.Cl_Delta().nupow(temp, Y1, c_);

    cl_.Cl_Delta().nucompinv(T1, T1, temp);

    cl_.Cl_Delta().nupow(T2, X2, u_);
    cl_.Cl_Delta().nupow(temp, Y2, c_);
    cl_.Cl_Delta().nucompinv(T2, T2, temp);

    init_random_oracle(X1, X2, Y1, Y2, T1, T2);

    // CL_.h() = X1 = g_q
    return c_ == query_random_oracle(C_);
}
