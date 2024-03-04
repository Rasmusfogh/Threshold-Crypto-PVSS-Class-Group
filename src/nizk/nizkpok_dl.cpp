#include "nizkpok_dl.hpp"

using namespace BICYCL;
using namespace OpenSSL;
using namespace UTILS;
using namespace NIZK;


NizkPoK_DL::NizkPoK_DL(HashAlgo& hash, RandGen &randgen, const CL_HSMqk &cl,
    const PublicKey& x, const SecretKey& w) : hash_(hash), CL_(cl)
{
    //Compute boundary A and AS
    Mpz::mul(A_, cl.encrypt_randomness_bound(), cl.encrypt_randomness_bound());
    Mpz::add(AS_, A_, cl.encrypt_randomness_bound());

    Mpz temp, r;
    QFI t;

    // //Could be parallelized I think
    for(size_t i = 0; i < rounds_; i++) {
        r = randgen.random_mpz(A_);
        cl.power_of_h(t, r);

        b_[i] = hash_(cl.h(), x.get(), t);
        Mpz::mul(temp, w, b_[i]);
        Mpz::add(u_[i], temp, r);
    }
}

bool NizkPoK_DL::verify(const PublicKey& x) const 
{
    Mpz h;
    QFI t1, t2;

    for(size_t i = 0; i < rounds_; i++) {

        if (u_[i] > AS_)
            return false;
                
        x.exponentiation(CL_, t1, b_[i]);
        CL_.power_of_h(t2, u_[i]);
        CL_.Cl_Delta().nucompinv(t1, t2, t1);

        //h = H(h, x, t_j = t1)
        h = hash_(CL_.h(), x.get(), t1);
        
        if (h != b_[i])
            return false;
    }

    return true;
}