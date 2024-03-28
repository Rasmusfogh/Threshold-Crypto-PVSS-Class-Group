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

    ECGroup ec_group_(seclevel);
    QCLPVSS_ext pvss(seclevel, H, randgen, ec_group_, q, 1, n, t);

    vector<unique_ptr<const SecretKey>> sks(n);
    vector<unique_ptr<const PublicKey>> pks(n);
    vector<unique_ptr<NizkPoK_DL>> keygen_pf(n);
    unique_ptr<vector<unique_ptr<const Share>>> sss_shares;
    vector<unique_ptr<const Share>> Ais(n); //on the form <i, Ai>
    vector<unique_ptr<Nizk_DLEQ>> dec_shares(n);
    vector<unique_ptr<ECPoint>> tpki;
    vector<unique_ptr<Mpz>> tski;

    tpki.reserve(n);
    generate_n(back_inserter(tpki), n, [&] {return unique_ptr<ECPoint>(new ECPoint(ec_group_)); });
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
        if(!(enc_shares_ext_matrix[i]->pf_->verify(pks, *enc_shares_ext_matrix[i]->Bs_, 
            *enc_shares_ext_matrix[i]->Ds_, enc_shares_ext_matrix[i]->R_))) {
            return EXIT_FAILURE;    
        }
    }

    //At this point, the set Q is assumed to all parties, as all are verifying here
    for(size_t i = 0; i < n; i++)
    {
        for(size_t j = 0; j < n; j++)
            ec_group_.ec_add(*tpki[i], *tpki[i], *enc_shares_ext_matrix[j]->Ds_->at(i));
    }

    //global public key
    ECPoint tpk(ec_group_);

    for(size_t i = 1; i < t + 1; i++)
    {
        Mpz numerator(1UL), denominator(1UL), ai(i);

        for(size_t k = 1; k < t + 1; k++)
        {
            if (i == k) continue;

            Mpz ak(k);
            Mpz::mul(numerator, numerator, ak);
            Mpz::sub(ak, ak, ai);
            Mpz::mul(denominator, denominator, ak);
        }

        Mpz::mod_inverse(denominator, denominator, q);
        Mpz::mul(numerator, numerator, denominator);
        Mpz::mod(numerator, numerator, q);

        ec_group_.scal_mul(tpk, BN(numerator), *tpki[i - 1]);
        //numerator is lambda i, raise to tpki
    }

    vector<vector<unique_ptr<QFI>>> shared_Bs;
    vector<QFI> shared_Rs;
    shared_Bs.reserve(n);
    shared_Rs.reserve(n);

    for(size_t i = 0; i < n; i++)
    {
        shared_Bs.emplace_back(vector<unique_ptr<QFI>>());
        shared_Bs[i].reserve(n);

        shared_Rs.emplace_back(enc_shares_ext_matrix[i]->R_);

        for (size_t j = 0; j < n; j++)
            shared_Bs[i].emplace_back(move(enc_shares_ext_matrix[i]->Bs_->at(j)));
    }


    for(size_t i = 0; i < n; i++)
        tski[i] = pvss.compute_sk(shared_Bs[i], shared_Rs, *sks[i]);
    

    for(size_t i = 0; i < n; i++)
    {
        ECPoint pk(ec_group_);
        ec_group_.scal_mul_gen(pk, BN(*tski[i]));

        if(!(ec_group_.ec_point_eq(pk, *tpki[i])))
            return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}