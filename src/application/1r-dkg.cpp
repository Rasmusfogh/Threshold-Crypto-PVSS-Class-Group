#include <qclpvss.hpp>
#include <chrono>
#include <secp256k1.h>
#include "utils.h"
#include <assert.h>
#include <secp256k1_wrapper.hpp>
using namespace QCLPVSS_;
using namespace BICYCL;
using namespace std;
using namespace std::chrono;
using namespace EC;
int main (int argc, char *argv[])
{
    Mpz seed;
    SecLevel seclevel(128);
    RandGen randgen;

    auto T = std::chrono::system_clock::now();
    seed = static_cast<unsigned long>(T.time_since_epoch().count());
    randgen.set_seed (seed);

    BICYCL::Mpz q(randgen.random_prime(129));

    OpenSSL::HashAlgo H (seclevel);

    size_t n(10UL);
    size_t t(5UL);

    //setup.1
    QCLPVSS pvss(seclevel, H, randgen, q, 1, n, t);
    Secp256k1 secp256k1;

    vector<unique_ptr<const SecretKey>> sks(n);
    vector<unique_ptr<const PublicKey>> pks(n);
    vector<unique_ptr<NizkPoK_DL>> keygen_pf(n);
    unique_ptr<vector<unique_ptr<const Share>>> sss_shares;
    vector<unique_ptr<const Share>> Ais(n); //on the form <i, Ai>
    vector<unique_ptr<Nizk_DLEQ>> dec_shares(n);
    const Mpz s(9898UL);

    //setup.2
    for(size_t i = 0; i < n; i++) 
    {
        sks[i] = pvss.keyGen(randgen);
        pks[i] = pvss.keyGen(*sks[i]);
        keygen_pf[i] = pvss.keyGen(*pks[i], *sks[i]);
    }

    //parties verifies key
    for(size_t i = 0; i < n; i++)
        if(!pvss.verifyKey(*pks[i], *keygen_pf[i]))
            return EXIT_FAILURE;    

    for(size_t i = 0; i < n; i++)
    {
        Mpz r = secp256k1.randomPoint();
        unique_ptr<vector<unique_ptr<const Share>>> shares = pvss.dist(r);
        unique_ptr<EncShares> enc_shares = pvss.dist(pks, *shares);

        for(size_t i = 0; i < n; i++)
        {
            Mpz Dij = secp256k1.exponent((*shares)[i]->second);
        }
    }

    // sss_shares = pvss.dist(s);
    // unique_ptr<Nizk_SH> sh_pf = pvss.dist(pks, *sss_shares);

    // if (!pvss.verifySharing(pks, *sh_pf))
    //     return EXIT_FAILURE;

    // for(size_t i = 0; i < n; i++)
    // {
    //     Ais[i] = pvss.decShare(*sks[i], i);
    //     dec_shares[i] = pvss.decShare(*pks[i], *sks[i], i);
    // }

    // unique_ptr<const Mpz> s_rec = pvss.rec(Ais);


    // for(size_t i = 0; i < n; i++)
    //     if (!pvss.verifyDec(*Ais[i], *pks[i], *dec_shares[i], i))
    //         return EXIT_FAILURE;

    return EXIT_SUCCESS;
}