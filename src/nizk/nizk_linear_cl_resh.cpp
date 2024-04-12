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

    // cout << T1 << endl << T2 << endl << T3 << endl;
    init_random_oracle(h, R0_, U, V, B0_, pk_, R, T1);
    c_ = query_random_oracle(C_);

    Mpz::mul(u_[0], c_, get<0>(w));
    Mpz::add(u_[0], u_[0], r0);

    Mpz::mul(u_[1], c_, get<1>(w));
    Mpz::add(u_[1], u_[1], r1);
}

bool NizkLinCLResh::verify(const QFI& U, const QFI& R0_, const QFI& B0_,
    const QFI& V, const QFI& h, const PublicKey& pk_, const QFI& R) const {

    QFI T1, T2, T3, T4, T_temp, Y_temp;

    // T1 for X = h, Y = V
    cl_.power_of_h(T1, u_[0]);
    cl_.power_of_h(T_temp, u_[1]);
    cl_.Cl_Delta().nucomp(T1, T1, T_temp);

    cl_.Cl_Delta().nupow(Y_temp, pk_.get(), c_);
    cl_.Cl_Delta().nucompinv(T1, T1, Y_temp);

    // T2 for X = R0_, Y = B0_
    cl_.Cl_Delta().nupow(T2, R0_, u_[0]);
    cl_.Cl_Delta().nupow(T_temp, R0_, u_[1]);
    cl_.Cl_Delta().nucomp(T2, T2, T_temp);

    cl_.Cl_Delta().nupow(Y_temp, B0_, c_);
    cl_.Cl_Delta().nucompinv(T2, T2, Y_temp);

    // T3 for X = U, Y = pk_
    cl_.Cl_Delta().nupow(T3, U, u_[0]);
    cl_.Cl_Delta().nupow(T_temp, U, u_[1]);
    cl_.Cl_Delta().nucomp(T3, T3, T_temp);

    cl_.Cl_Delta().nupow(Y_temp, pk_.get(), c_);
    cl_.Cl_Delta().nucompinv(T3, T3, Y_temp);

    // T4 for X = h, Y = R
    cl_.power_of_h(T4, u_[0]);
    cl_.power_of_h(T_temp, u_[1]);
    cl_.Cl_Delta().nucomp(T4, T4, T_temp);

    cl_.Cl_Delta().nupow(Y_temp, R, c_);
    cl_.Cl_Delta().nucompinv(T4, T4, Y_temp);

    // cout << T1 << endl << T2 << endl << T3 << endl << T4 << endl;
    init_random_oracle(h, R0_, U, V, B0_, pk_, R, T1);

    Mpz c = query_random_oracle(C_);

    return c == c_;
}