#include "nizkpok_dl.hpp"

using namespace BICYCL;
using namespace OpenSSL;
using namespace UTILS;
using namespace NIZK;


NizkPoK_DL::NizkPoK_DL(HashAlgo & hash, RandGen &randgen, const CL_HSMqk &cl_hsm,
    const SecLevel & seclevel, const PublicKey& x, const SecretKey& w) : h_(hash)
{
    //Compute boundary A and AS
    Mpz::mul(A_, cl_hsm.encrypt_randomness_bound(), cl_hsm.encrypt_randomness_bound());
    Mpz::add(AS_, A_, cl_hsm.encrypt_randomness_bound());

    Mpz temp, r;
    QFI t;

    // //Could be parallelized I think
    for(size_t i = 0; i < rounds_; i++) {
        r = randgen.random_mpz(A_);
        cl_hsm.power_of_h(t, r);

        b_[i] = h_(cl_hsm.h(), x.get(), t);

        Mpz::mul(temp, w, b_[i]);
        Mpz::add(u_[i], temp, r);
    }
}

bool NizkPoK_DL::verify(const CL_HSMqk &cl_hsm, const PublicKey& x) const 
{
    Mpz temp, h;
    QFI t1, t2;

    for(size_t i = 0; i < rounds_; i++) {

        if (u_[i] > AS_)
            return false;
                
        temp = b_[i];
        temp.neg();

        //t1 = x^(-b_j)
        x.exponentiation(cl_hsm, t1, temp);

        //t2 = h^(u_j)
        cl_hsm.power_of_h(t2, u_[i]);

        //t1 = t1 * t2
        cl_hsm.Cl_Delta().nucomp(t1, t1, t2);

        //h = H(h, x, t_j = t1)
        h = h_(cl_hsm.h(), x.get(), t1);
        
        if (h != b_[i])
            return false;
    }

    return true;
}