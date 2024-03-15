#include "../qclpvss.hpp"
#include <chrono>
#include <secp256k1.h>
#include "utils.h"
#include <assert.h>
using namespace QCLPVSS_;
using namespace BICYCL;
using namespace std;
using namespace std::chrono;

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
    QCLPVSS pvss(seclevel, H, randgen, q, 1, n, t, false);

    unsigned char randomize[32];
    int return_val;
    //Create context
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);

    // Randomizing the context is recommended to protect against side-channel leakage 
    if (!fill_random(randomize, sizeof(randomize))) {
        printf("Failed to generate randomness\n");
        return 1;
    }

    return_val = secp256k1_context_randomize(ctx, randomize);
    assert(return_val);

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
        //Picking randomness
        unsigned char r_[32];
        while (1) {
            if (!fill_random(r_, sizeof(r_))) {
                printf("Failed to generate randomness\n");
                return EXIT_FAILURE;
            }
            if (secp256k1_ec_seckey_verify(ctx, r_)) {
                break;
            }
        }
        
        Mpz r(vector<unsigned char>(r_, r_ + 32));

        
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