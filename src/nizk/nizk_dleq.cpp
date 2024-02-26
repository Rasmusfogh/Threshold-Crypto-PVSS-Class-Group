#include "nizk_dleq.hpp"

using namespace NIZK;


Nizk_DLEQ::Nizk_DLEQ(HashAlgo &hash, RandGen &randgen, const CL_HSMqk &cl_hsm,
    const SecLevel & seclevel, vector<QFI>& Us, const QFI& R, vector<QFI>& Vs, const Mpz& r) : h_(hash)
{
    
}

bool Nizk_DLEQ::verify(const CL_HSMqk &cl_hsm, vector<QFI>& Us, QFI& R, vector<QFI>& Vs, Mpz& r) const
{

}