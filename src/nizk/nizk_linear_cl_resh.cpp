#include "nizk_linear_cl_resh.hpp"

using namespace NIZK;

NizkLinCLResh::NizkLinCLResh(HashAlgo& hash, RandGen& rand, const CL_HSMqk& cl,
    const SecLevel& seclevel)
    : BaseLinCL(hash, rand, cl, seclevel, 2) {}

void NizkLinCLResh::prove(const Witness& w, const QFI& U, const QFI& R0_,
    const QFI& B0_, const QFI& V, const QFI& h, const PublicKey& pk_,
    const QFI& R) {

    Mpz r0 = rand_.random_mpz(A_);
    Mpz r1 = rand_.random_mpz(A_);

    QFI T1, T2, T3, T_temp;

    cl_.power_of_h(T1, r0);
    cl_.power_of_h(T_temp, r1);
    cl_.Cl_Delta().nucomp(T1, T1, T_temp);

    cl_.Cl_Delta().nupow(T2, R0_, r0);
    cl_.Cl_Delta().nupow(T_temp, R0_, r1);
    cl_.Cl_Delta().nucomp(T2, T2, T_temp);

    cl_.Cl_Delta().nupow(T3, U, r0);
    cl_.Cl_Delta().nupow(T_temp, U, r1);
    cl_.Cl_Delta().nucomp(T3, T3, T_temp);

    init_random_oracle(h, R0_, U, V, B0_, pk_, R, T1, T2, T3);
    c_ = query_random_oracle(C_);

    Mpz::mul(u_[0], c_, get<0>(w));
    Mpz::add(u_[0], u_[0], r0);

    Mpz::mul(u_[1], c_, get<1>(w));
    Mpz::add(u_[1], u_[1], r1);
}

bool NizkLinCLResh::verify(const QFI& U, const QFI& R0_, const QFI& B0_,
    const QFI& V, const QFI& h, const PublicKey& pk_, const QFI& R) const {

    QFI T1, T2, T3, T_temp;

    cl_.power_of_h(T1, u_[0]);
    cl_.power_of_h(T_temp, u_[1]);
    cl_.Cl_Delta().nucomp(T1, T1, T_temp);

    // cl_.Cl_Delta().nupow(temp, Y1, c_);
}