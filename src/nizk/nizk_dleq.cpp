#include "nizk_dleq.hpp"
#include <cmath>
using namespace NIZK;


Nizk_DLEQ::Nizk_DLEQ(HashAlgo &hash, RandGen &randgen, const CL_HSMqk &cl_hsm,
    const QFI& U, const QFI& R, const QFI& V, const Mpz& r) : h_(hash)
{
    Mpz::mul(A_, cl_hsm.encrypt_randomness_bound(), cl_hsm.encrypt_randomness_bound());

    Mpz r_(randgen.random_mpz(A_));

    QFI T1, T2;
    //g_q^r_
    cl_hsm.power_of_h(T1, r_);
    //U^r_
    cl_hsm.Cl_Delta().nupow(T2, U, r_);
    
    c_ = h_(cl_hsm.h(), U, R, V, T1, T2);

    Mpz::mul(u_, c_, r);
    Mpz::add(u_, u_, r_);

    //Not sure of c_ and u_ persist
}

Nizk_DLEQ::Nizk_DLEQ(HashAlgo& hash, RandGen& randgen, const CL_HSMqk& cl_hsm,
    const QFI& R, const PublicKey& pki, QFI& Mi, const SecretKey& sk): h_(hash)
{
    
}

bool Nizk_DLEQ::verify(const CL_HSMqk &cl_hsm, const QFI& U, const QFI& R, const QFI& V) const
{
    //Not sure that this boundary is correctly computed, prob not
    Mpz SC, boundary;
    Mpz C((unsigned long) std::pow(2., h_.digest_nbits()));
    Mpz::mul(SC, cl_hsm.encrypt_randomness_bound(), C);
    Mpz::add(boundary, A_, SC);

    if(u_ > boundary)
        return false;

    QFI T1, T2, temp;

    Mpz c_neg(c_);
    c_neg.neg();

    cl_hsm.power_of_h(T1, u_);
    cl_hsm.Cl_Delta().nupow(temp, R, c_neg);
    cl_hsm.Cl_Delta().nucomp(T1, temp, T1);

    cl_hsm.Cl_Delta().nupow(T2, U, u_);
    cl_hsm.Cl_Delta().nupow(temp, V, c_neg);
    cl_hsm.Cl_Delta().nucomp(T2, temp, T2);

    return c_ == Mpz(h_(cl_hsm.h(), U, R, V, T1, T2));
}

bool Nizk_DLEQ::verify(const CL_HSMqk &cl_hsm, QFI& R, const PublicKey& pki, QFI& Mi) const
{
    return true;
}

