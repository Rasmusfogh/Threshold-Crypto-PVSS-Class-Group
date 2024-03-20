#include <qclpvss.hpp>
#include <chrono>
#include <secp256k1.h>
#include <assert.h>
#include <memory>
#include <secp256k1_wrapper.hpp>
#include <nizk_sh_ext.hpp>
#include "utils.h"

using namespace QCLPVSS_;
using namespace BICYCL;
using namespace std;
using namespace std::chrono;
using namespace EC;
using namespace NIZK;

int main (int argc, char *argv[])
{
    Mpz seed;
    SecLevel seclevel(128);
    RandGen randgen;

    auto T = std::chrono::system_clock::now();
    seed = static_cast<unsigned long>(T.time_since_epoch().count());
    randgen.set_seed (seed);

    BICYCL::Mpz q(randgen.random_prime(seclevel.soundness() * 2));

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

    vector<vector<Mpz>> Dij_matrix(n, vector<Mpz>(n));
    vector<unique_ptr<EncSharesExt>> enc_shares_ext_matrix(n);
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
        //Mpz r = secp256k1.randomPoint();
        Mpz s = (randgen.random_mpz(q));
        unique_ptr<vector<unique_ptr<const Share>>> shares = pvss.dist(s);
        enc_shares_ext_matrix[i] = pvss.dist(pks, *shares);

        for(size_t j = 0; j < n; j++)
        {
            Dij_matrix[i][j] = secp256k1.exponent((*shares)[j]->second);
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