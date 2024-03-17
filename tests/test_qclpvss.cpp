#include <string>
#include <iostream>
#include <chrono>
#include <memory>
#include "../src/qclpvss.hpp"

using namespace BICYCL;
using namespace QCLPVSS_;

using namespace std;
using std::string;
using namespace std::chrono;

int main (int argc, char *argv[])
{
    BICYCL::Mpz seed;
    size_t qsize = 0;
    size_t k = 1;
    SecLevel seclevel(128);
    BICYCL::RandGen randgen;

    bool compact_variant = false; /* by default the compact variant is not used */

    auto T = std::chrono::system_clock::now();
    seed = static_cast<unsigned long>(T.time_since_epoch().count());

    /* */
    std::cout << "# Using seed = " << seed << std::endl;
    randgen.set_seed (seed);

    BICYCL::Mpz q(randgen.random_prime(129));

    /* */
    std::cout << "# security: " << seclevel << " bits" << std::endl;

    /* q and qsize are mutually exclusive */
    if ((q.sgn() != 0 && qsize != 0) || (q.is_zero() && qsize == 0))
    {
        std::cerr << "Error, exactly one of q or qsize must be provided"
                << std::endl;
        return EXIT_FAILURE;
    }


    /* If q is given, it should be prime */
    if (q.sgn() != 0 && (q.sgn() < 0 || !q.is_prime()))
    {
        std::cerr << "Error, q must be positive and prime" << std::endl;
        return EXIT_FAILURE;
    }

    OpenSSL::HashAlgo H (seclevel);

    size_t n(10UL);
    size_t t(5UL);

    QCLPVSS pvss(seclevel, H, randgen, q, k, n, t, compact_variant);

    //std::cout << pvss.CL_;

    vector<unique_ptr<const SecretKey>> sks(n);
    vector<unique_ptr<const PublicKey>> pks(n);
    vector<unique_ptr<NizkPoK_DL>> keygen_pf(n);
    unique_ptr<vector<unique_ptr<const Share>>> sss_shares;
    vector<unique_ptr<DecShare>> dec_shares(n);
    vector<unique_ptr<const Share>> rec_shares;

    const Mpz s(9898UL);


    for(size_t i = 0; i < n; i++) 
    {
        sks[i] = pvss.keyGen(randgen);
        pks[i] = pvss.keyGen(*sks[i]);
        keygen_pf[i] = pvss.keyGen(*pks[i], *sks[i]);
    }

    for(size_t i = 0; i < n; i++)
        if(!pvss.verifyKey(*pks[i], *keygen_pf[i]))
            return EXIT_FAILURE;    

    sss_shares = pvss.dist(s);
    unique_ptr<EncShares> enc_shares = pvss.dist(pks, *sss_shares);

    if (!pvss.verifySharing(*enc_shares, pks))
        return EXIT_FAILURE;

    for(size_t i = 0; i < n; i++)
        dec_shares[i] = pvss.decShare(*pks[i], *sks[i], enc_shares->R, enc_shares->Bs[i], i);

    for (const auto& dec_share : dec_shares) {
        if (dec_share->sh) {
            rec_shares.push_back(unique_ptr<const Share> (new Share(*dec_share->sh)));
        }
    }

    unique_ptr<const Mpz> s_rec = pvss.rec(rec_shares);


    for(size_t i = 0; i < n; i++)
        if (!pvss.verifyDec(*dec_shares[i], *pks[i], enc_shares->R, enc_shares->Bs[i]))
            return EXIT_FAILURE;

    return EXIT_SUCCESS;
}