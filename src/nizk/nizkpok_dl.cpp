#include "nizkpok_dl.hpp"

using namespace BICYCL;
using namespace OpenSSL;
using namespace UTILS;
using namespace NIZKPOK_DL_;


NizkPoK_DL::NizkPoK_DL(HashAlgo & hash, RandGen &randgen, const CL_HSMqk &cl_hsm,
                const SecLevel & seclevel, const PublicKey &x, const SecretKey &w) : h_(hash) 
{
    size_t l(30);
    std::vector<Mpz> r;
    std::vector<QFI> t;

    // r <- [0 ... upper_bound*2^(seclevel-2) - 1]

    //bound = upper_bound*2^(seclevel-2)
    Mpz::mulby2k(A_, cl_hsm.encrypt_randomness_bound(), seclevel.soundness() - 2UL);

    //Could be parallelized I think
    for(size_t i = 0; i < l; i++) {
        // r = [1 ... upper_bound*2^(seclevel-2)]
        Mpz::add(r[i], randgen.random_mpz(A_), Mpz(1UL));
        cl_hsm.power_of_h(t[i], r[i]);
        b_[i] = h_(cl_hsm.h().a(), cl_hsm.h().b(), cl_hsm.h().c(), 
                    x.get().a(), x.get().b(), x.get().c(), 
                    t[i].a(), t[i].b(), t[i].c());

        Mpz temp;
        Mpz::mul(temp, w, b_[i]);
        Mpz::add(u_[i], temp, r[i]);
    }
}

bool NizkPoK_DL::Verify(const CL_HSMqk &cl_hsm, const PublicKey &x) const 
{
    
    size_t l(30);
    Mpz bound;

    Mpz::add(bound, A_, cl_hsm.encrypt_randomness_bound());

    for(size_t i = 0; i < l; i++) {
        if (u_[i] > bound)
            return false;
        
        QFI t1, t2;

        x.exponentiation(cl_hsm, t1, u_[i]);

        Mpz b_temp(b_[i]);
        b_temp.neg();
        cl_hsm.power_of_h(t2, b_temp);
    }
    //TODO u in [-SC,SC+A]
    Mpz u;

    //TODO t=(x^-c)*(h^u)
    QFI t;

    Mpz c (h_(cl_hsm.h().a(), cl_hsm.h().b(), cl_hsm.h().c(), x.get().a(), x.get().b(), x.get().c(), t.a(), t.b(), t.c()));

    return true;
}