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

    Mpz temp;
    vector<Mpz> r(rounds_);
    vector<QFI> t(rounds_);

    // //Could be parallelized I think
    for(size_t i = 0; i < rounds_; i++) 
    {
        r[i] = randgen.random_mpz(A_);
        cl.power_of_h(t[i], r[i]);
    }

    Mpz seed(hash_(cl.h(), x.get(), t));
    randgen.set_seed(seed);

    for(size_t i = 0; i < rounds_; i++)
    {
        b_[i] = randgen.random_mpz(cl.q()); // not right boundary
        Mpz::mul(temp, w, b_[i]);
        Mpz::add(u_[i], temp, r[i]);
    }
}

bool NizkPoK_DL::verify(RandGen &randgen, const PublicKey& x) const 
{
    vector<QFI> t(rounds_);
    QFI temp;

    for(size_t i = 0; i < rounds_; i++) {

        cout << u_[i].nbits() << endl;
        cout << AS_.nbits() << endl;

        if (u_[i] > AS_) return false;
                
        x.exponentiation(CL_, t[i], b_[i]);
        CL_.power_of_h(temp, u_[i]);
        CL_.Cl_Delta().nucompinv(t[i], temp, t[i]);
    }

    Mpz seed(hash_(CL_.h(), x.get(), t));
    randgen.set_seed(seed);

    for(size_t i = 0; i < rounds_; i++)
        if (b_[i] != randgen.random_mpz(CL_.q()))
            return false;
    
    return true;
}