#include "nizkpok_dl.hpp"

using namespace BICYCL;
using namespace OpenSSL;
using namespace UTILS;
using namespace NIZKPOK_DL_;


NizkPoK_DL::NizkPoK_DL(HashAlgo & hash, RandGen &randgen, const CL_HSMqk &cl_hsm,
                const PublicKey &x, const SecretKey &w) : h_(hash) 
{
    QFI t;

    // r <- [0 ... secretkey_bound - 1]
    Mpz r (randgen.random_mpz(cl_hsm.secretkey_bound()));

    // r = [1 ... secretkey_bound]
    Mpz::add(r, r, Mpz(1UL));

    cl_hsm.power_of_h(t, r);


    //Random oracle model by using hash function
    c_ = h_(cl_hsm.h().a(), cl_hsm.h().b(), cl_hsm.h().c(), x.get().a(), x.get().b(), x.get().c(), t.a(), t.b(), t.c()); //maybe cl_hsm.h().a(), cl_hsm.h().b(), cl_hsm.h().c(), x.get().a(), x.get().b(), x.get().c(), t.a(), t.b(), t.c()

    u_ = r; 
    //u = r + cw
    Mpz::addmul(u_, c_, w);
}

bool NizkPoK_DL::Verify(const CL_HSMqk &cl_hsm, const PublicKey &x) const 
{
    //TODO u in [-SC,SC+A]
    Mpz u;

    //TODO t=(x^-c)*(h^u)
    QFI t;

    Mpz c (h_(cl_hsm.h().a(), cl_hsm.h().b(), cl_hsm.h().c(), x.get().a(), x.get().b(), x.get().c(), t.a(), t.b(), t.c()));

    return c_ == c;
}