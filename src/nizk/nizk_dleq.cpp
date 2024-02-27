#include "nizk_dleq.hpp"

using namespace NIZK;


Nizk_DLEQ::Nizk_DLEQ(HashAlgo &hash, RandGen &randgen, const CL_HSMqk &cl_hsm,
    const SecLevel & seclevel, vector<QFI>& Us, const QFI& R, vector<QFI>& Vs, const Mpz& r) : h_(hash)
{
    Mpz::mul(A_, cl_hsm.encrypt_randomness_bound(), cl_hsm.encrypt_randomness_bound());

    Mpz r_(randgen.random_mpz(A_));

}

Nizk_DLEQ::Nizk_DLEQ(HashAlgo& hash, RandGen& randgen, const CL_HSMqk& cl_hsm, const SecLevel& seclevel,
    const QFI& R, const PublicKey& pki, QFI& Mi, const SecretKey& sk): h_(hash)
{
    
}

bool Nizk_DLEQ::verify(const CL_HSMqk &cl_hsm, vector<QFI>& Us, QFI& R, vector<QFI>& Vs,unique_ptr<Nizk_SH>& pf) const
{
    return true;
}

bool Nizk_DLEQ::verify(const CL_HSMqk &cl_hsm, QFI& R, const PublicKey& pki, QFI& Mi) const
{
    return true;
}