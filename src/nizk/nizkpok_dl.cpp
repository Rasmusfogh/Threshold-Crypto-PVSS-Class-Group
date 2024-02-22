#include "nizkpok_dl.hpp"

using namespace BICYCL;
using namespace OpenSSL;
using namespace UTILS;
using namespace NIZKPOK_DL_;


NizkPoK_DL::NizkPoK_DL(HashAlgo & hash, RandGen &randgen, const CL_HSMqk &cl_hsm,
    const SecLevel & seclevel, const PublicKey &x, const SecretKey &w) : h_(hash)
{
    //Compute boundary to be
    Mpz::mul(A_, cl_hsm.encrypt_randomness_bound(), cl_hsm.encrypt_randomness_bound());

    Mpz temp, r;
    QFI t;

    // //Could be parallelized I think
    for(size_t i = 0; i < rounds_; i++) {
        // r = [1 ... A_]
        r = randgen.random_mpz(A_);
        cl_hsm.power_of_h(t, r);

        b_[i] = h_(cl_hsm.h().a(), cl_hsm.h().b(), cl_hsm.h().c(), 
                     x.get().a(), x.get().b(), x.get().c(), 
                     t.a(), t.b(), t.c());

        Mpz::mul(temp, w, b_[i]);
        Mpz::add(u_[i], temp, r);
    }
}

bool NizkPoK_DL::Verify(const CL_HSMqk &cl_hsm, const PublicKey &x) const 
{
    //bound = [A + S]
    Mpz bound;
    Mpz::add(bound, A_, cl_hsm.encrypt_randomness_bound());

    for(size_t i = 0; i < rounds_; i++) {

        if (u_[i] > bound)
            return false;
        
        QFI t1, t2;
        
        Mpz b_temp(b_[i]);
        b_temp.neg();

        //t1 = x^(-b_j)
        x.exponentiation(cl_hsm, t1, b_temp);

        //t2 = h^(u_j)
        cl_hsm.power_of_h(t2, u_[i]);

        //t1 = t1 * t2
        cl_hsm.Cl_Delta().nucomp(t1, t1, t2);

        //h = H(h, x, t_j = t1)
        Mpz h (h_(cl_hsm.h().a(), cl_hsm.h().b(), cl_hsm.h().c(), 
                    x.get().a(), x.get().b(), x.get().c(), 
                    t1.a(), t1.b(), t1.c()));
        
        if (h != b_[i])
            return false;
    }

    return true;
}