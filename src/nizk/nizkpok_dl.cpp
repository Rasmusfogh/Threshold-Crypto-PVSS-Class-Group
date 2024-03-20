#include "nizkpok_dl.hpp"

using namespace BICYCL;
using namespace OpenSSL;
using namespace UTILS;
using namespace NIZK;


NizkPoK_DL::NizkPoK_DL(HashAlgo& hash, RandGen &rand, const CL_HSMqk &cl) 
    : Nizk_base(hash, rand, cl)
{
    //Compute boundary A and AS
    Mpz::mul(A_, cl.encrypt_randomness_bound(), cl.encrypt_randomness_bound());
    Mpz::add(AS_, A_, cl.encrypt_randomness_bound());
}

void NizkPoK_DL::prove(const SecretKey& sk, const PublicKey& pk)
{
    Mpz temp;
    vector<Mpz> r(rounds_);
    vector<QFI> t(rounds_);

    for(size_t i = 0; i < rounds_; i++) 
    {
        r[i] = rand_.random_mpz(A_);
        cl_.power_of_h(t[i], r[i]);
    }
    
    initRandomOracle(cl_.h(), pk.get(), t);

    for(size_t i = 0; i < rounds_; i++)
    {
        b_[i] = queryRandomOracle(cl_.q()); // not right boundary
        Mpz::mul(temp, sk, b_[i]);
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