#include "nizk_dleq.hpp"
#include <cmath>
using namespace NIZK;


Nizk_DLEQ::Nizk_DLEQ(HashAlgo &hash, RandGen &randgen, const CL_HSMqk &cl,
    const QFI& U, const QFI& R, const QFI& V, const Mpz& r) : hash_(hash), CL_(cl)
{
    Mpz::mul(A_, cl.encrypt_randomness_bound(), cl.encrypt_randomness_bound());

    Mpz r_(randgen.random_mpz(A_));

    QFI T1, T2;
    //g_q^r_
    cl.power_of_h(T1, r_);
    //U^r_
    cl.Cl_Delta().nupow(T2, U, r_);
    
    c_ = hash_(cl.h(), U, R, V, T1, T2);

    Mpz::mul(u_, c_, r);
    Mpz::add(u_, u_, r_);

    //Not sure of c_ and u_ persist
}

Nizk_DLEQ::Nizk_DLEQ(HashAlgo& hash, RandGen& randgen, const CL_HSMqk& cl,
    const QFI& R, const PublicKey& pki, QFI& Mi, const SecretKey& sk): hash_(hash), CL_(cl)
{
    
}

bool Nizk_DLEQ::verify(const QFI& U, const QFI& R, const QFI& V) const
{
    //Not sure that this boundary is correctly computed, prob not
    Mpz SC, boundary;
    Mpz C((unsigned long) std::pow(2., hash_.digest_nbits()));
    Mpz::mul(SC, CL_.encrypt_randomness_bound(), C);
    Mpz::add(boundary, A_, SC);

    if(u_ > boundary)
        return false;

    QFI T1, T2, temp;

    Mpz c_neg(c_);
    c_neg.neg();

    CL_.power_of_h(T1, u_);
    CL_.Cl_Delta().nupow(temp, R, c_neg);
    CL_.Cl_Delta().nucomp(T1, temp, T1);

    CL_.Cl_Delta().nupow(T2, U, u_);
    CL_.Cl_Delta().nupow(temp, V, c_neg);
    CL_.Cl_Delta().nucomp(T2, temp, T2);

    return c_ == Mpz(hash_(CL_.h(), U, R, V, T1, T2));
}

bool Nizk_DLEQ::verify(QFI& R, const PublicKey& pki, QFI& Mi) const
{
    return true;
}

