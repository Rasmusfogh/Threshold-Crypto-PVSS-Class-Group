#include "nizkpok_dl.hpp"

using namespace BICYCL;
using namespace OpenSSL;
using namespace UTILS;
using namespace NIZK;


NizkPoK_DL::NizkPoK_DL(HashAlgo& hash, RandGen &rand, const CL_HSMqk &cl,
    const PublicKey& x, const SecretKey& w) 
    : Nizk_base(hash, rand, cl)
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
        r[i] = rand.random_mpz(A_);
        cl.power_of_h(t[i], r[i]);
    }
    
    initRandomOracle(cl.h(), x.get(), t);

    for(size_t i = 0; i < rounds_; i++)
    {
        b_[i] = queryRandomOracle(cl.q()); // not right boundary
        Mpz::mul(temp, w, b_[i]);
        Mpz::add(u_[i], temp, r[i]);
    }
}

bool NizkPoK_DL::verify(const PublicKey& x) const
{
    vector<QFI> t(rounds_);
    QFI temp;

    for(size_t i = 0; i < rounds_; i++) {

        if (u_[i] > AS_) return false;
                
        x.exponentiation(cl_, t[i], b_[i]);
        cl_.power_of_h(temp, u_[i]);
        cl_.Cl_Delta().nucompinv(t[i], temp, t[i]);
    }

    initRandomOracle(cl_.h(), x.get(), t);

    for(size_t i = 0; i < rounds_; i++)
        if (b_[i] != queryRandomOracle(cl_.q()))
            return false;
    
    return true;
}