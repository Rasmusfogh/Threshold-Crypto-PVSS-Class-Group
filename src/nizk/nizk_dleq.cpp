#include "nizk_dleq.hpp"
#include <cmath>
using namespace NIZK;

/** X = (g_q/h, U) ; Y = (R, V) ; w = (r)  */
Nizk_DLEQ::Nizk_DLEQ(HashAlgo &hash, RandGen &randgen, const CL_HSMqk &cl,
    const QFI& U, const QFI& R, const QFI& V, const Mpz& witness) : hash_(hash), CL_(cl)
{
    Mpz::mul(A_, cl.encrypt_randomness_bound(), cl.encrypt_randomness_bound());

    Mpz r(randgen.random_mpz(A_));

    QFI T1, T2;
    //g_q^r_
    cl.power_of_h(T1, r);
    //U^r_
    cl.Cl_Delta().nupow(T2, U, r);
    
    //H(X, Y, T) = H((g_q(h), U), (R, V), (T1, T2))
    c_ = hash_(cl.h(), U, R, V, T1, T2);

    //u = r + cw
    Mpz::mul(u_, c_, witness);
    Mpz::add(u_, u_, r);
}

/** X = (g_q/h, R) ; Y = (pk_i, M_i) ; w = (sk_i)  */
Nizk_DLEQ::Nizk_DLEQ(HashAlgo& hash, RandGen& randgen, const CL_HSMqk& cl,
    const QFI& R, const PublicKey& pki, QFI& Mi, const SecretKey& witness): hash_(hash), CL_(cl)
{
    Mpz::mul(A_, cl.encrypt_randomness_bound(), cl.encrypt_randomness_bound());

    Mpz r(randgen.random_mpz(A_));

    QFI T1, T2;
    //g_q^r_
    cl.power_of_h(T1, r);
    //R^r_
    cl.Cl_Delta().nupow(T2, R, r);
    
    //H(X, Y, T) = H((g_q(h), R), (pk_i, M_i), (T1, T2))
    c_ = hash_(cl.h(), R, pki.get(), Mi, T1, T2);

    //u = r + cw
    Mpz::mul(u_, c_, witness);
    Mpz::add(u_, u_, r);
}

/** X = (g_q/h, U) ; Y = (R, V) ; w = (r)  */
bool Nizk_DLEQ::verify(const QFI& U, const QFI& R, const QFI& V) const
{
    //Not sure that this boundary is correctly computed, prob not
    Mpz SC(1UL), boundary(0UL);
    Mpz C(CL_.encrypt_randomness_bound());
    Mpz::mul(SC, CL_.encrypt_randomness_bound(), C);
    Mpz::add(boundary, A_, SC);

    cout << u_.nbits() << endl;
    cout << A_.nbits() << endl;
    cout << SC.nbits() << endl;
    cout << boundary.nbits() << endl;

    if(u_ > boundary)
        return false;

    QFI T1, T2, temp;

    CL_.power_of_h(T1, u_);
    CL_.Cl_Delta().nupow(temp, R, c_);
    CL_.Cl_Delta().nucompinv(T1, T1, temp);

    CL_.Cl_Delta().nupow(T2, U, u_);
    CL_.Cl_Delta().nupow(temp, V, c_);
    CL_.Cl_Delta().nucompinv(T2, T2, temp);

    return c_ == Mpz(hash_(CL_.h(), U, R, V, T1, T2));
}

/** X = (g_q/h, R) ; Y = (pk_i, M_i) ; w = (sk_i)  */
bool Nizk_DLEQ::verify(QFI& R, const PublicKey& pki, QFI& Mi) const
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
    CL_.Cl_Delta().nupow(temp, pki.get(), c_);
    CL_.Cl_Delta().nucompinv(T1, T1, temp);

    CL_.Cl_Delta().nupow(T2, R, u_);
    CL_.Cl_Delta().nupow(temp, Mi, c_);
    CL_.Cl_Delta().nucompinv(T2, T2, temp);

    return c_ == Mpz(hash_(CL_.h(), R, pki.get(), Mi, T1, T2));
}

