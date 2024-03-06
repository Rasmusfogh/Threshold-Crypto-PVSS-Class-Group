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
    vector<unique_ptr<const Share>> Ais(n); //on the form <i, Ai>
    vector<unique_ptr<Nizk_DLEQ>> dec_shares(n);
    const Mpz s(9898UL);

    auto start1 = high_resolution_clock::now();

    for(size_t i = 0; i < n; i++) 
    {
        sks[i] = pvss.keyGen(randgen);
        pks[i] = pvss.keyGen(*sks[i]);
        keygen_pf[i] = pvss.keyGen(*pks[i], *sks[i]);
    }

    auto stop1 = high_resolution_clock::now();
    auto duration1 = duration_cast<milliseconds>(stop1 - start1);
    cout << "keyGen: " << duration1.count() << endl;

    auto start2 = high_resolution_clock::now();

    for(size_t i = 0; i < n; i++)
        if(!pvss.verifyKey(*pks[i], *keygen_pf[i]))
            return EXIT_FAILURE;    

    auto stop2 = high_resolution_clock::now();
    auto duration2 = duration_cast<milliseconds>(stop2 - start2);
    cout << "verifyKey: " << duration2.count() << endl;

    auto start3 = high_resolution_clock::now();

    sss_shares = pvss.dist(s);
    unique_ptr<Nizk_SH> sh_pf = pvss.dist(pks, *sss_shares);

    auto stop3 = high_resolution_clock::now();
    auto duration3 = duration_cast<milliseconds>(stop3 - start3);
    cout << "dist: " << duration3.count() << endl;

    auto start4 = high_resolution_clock::now();

    if (!pvss.verifySharing(pks, move(sh_pf)))
        return EXIT_FAILURE;

    auto stop4 = high_resolution_clock::now();
    auto duration4 = duration_cast<milliseconds>(stop4 - start4);
    cout << "verifySharing: " << duration4.count() << endl;
    
    auto start5 = high_resolution_clock::now();

    for(size_t i = 0; i < n; i++)
    {
        Ais[i] = pvss.decShare(*sks[i], i);
        dec_shares[i] = pvss.decShare(*pks[i], *sks[i], i);
    }

    auto stop5 = high_resolution_clock::now();
    auto duration5 = duration_cast<milliseconds>(stop5 - start5);
    cout << "decShare: " << duration5.count() << endl;

    auto start6 = high_resolution_clock::now();

    unique_ptr<const Mpz> s_rec = pvss.rec(Ais);

    auto stop6 = high_resolution_clock::now();
    auto duration6 = duration_cast<milliseconds>(stop6 - start6);
    cout << "rec: " << duration6.count() << endl;

    auto start7 = high_resolution_clock::now();

    for(size_t i = 0; i < n; i++)
        if (!pvss.verifyDec(*Ais[i], *pks[i], *dec_shares[i], i))
            return EXIT_FAILURE;
    
    auto stop7 = high_resolution_clock::now();
    auto duration7 = duration_cast<milliseconds>(stop7 - start7);
    cout << "verifyDec: " << duration7.count() << endl;

    return EXIT_SUCCESS;
}