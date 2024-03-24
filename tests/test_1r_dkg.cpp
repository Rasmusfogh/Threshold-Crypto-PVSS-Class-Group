#include "../src/application/qclpvss_ext.hpp"
#include <chrono>
#include <secp256k1.h>
#include <assert.h>
#include <memory>
#include <nizk_sh_ext.hpp>

using namespace QCLPVSS_;
using namespace BICYCL;
using namespace std;
using namespace std::chrono;
using namespace NIZK;

int main (int argc, char *argv[])
{
    Mpz seed;
    SecLevel seclevel(128);
    RandGen randgen;

    auto T = std::chrono::system_clock::now();
    seed = static_cast<unsigned long>(T.time_since_epoch().count());
    randgen.set_seed (seed);

    BICYCL::Mpz q(randgen.random_prime(256));

    OpenSSL::HashAlgo H (seclevel);

    size_t n(10UL);
    size_t t(5UL);

    QCLPVSS_ext pvss(seclevel, H, randgen, q, 1, n, t);

    vector<unique_ptr<const SecretKey>> sks(n);
    vector<unique_ptr<const PublicKey>> pks(n);
    vector<unique_ptr<NizkPoK_DL>> keygen_pf(n);
    unique_ptr<vector<unique_ptr<const Share>>> sss_shares;
    vector<unique_ptr<const Share>> Ais(n); //on the form <i, Ai>
    vector<unique_ptr<Nizk_DLEQ>> dec_shares(n);
    const Mpz s(9898UL);

    vector<unique_ptr<EncSharesExt>> enc_shares_ext_matrix(n);

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
         enc_shares_ext_matrix[i] = pvss.share(pks);

    for(size_t i = 0; i < n; i++)
    {
        if(!(enc_shares_ext_matrix[i]->pf->verify(pks, enc_shares_ext_matrix[i]->Bs, 
                                                enc_shares_ext_matrix[i]->Ds, 
                                                enc_shares_ext_matrix[i]->R)))
        {
            return EXIT_FAILURE;    
        }

    }
    return EXIT_SUCCESS;
}