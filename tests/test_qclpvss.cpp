#include <string>
#include <iostream>
#include <chrono>
#include <memory>
#include "../src/qclpvss.hpp"

using namespace BICYCL;
using namespace QCLPVSS_;

using std::string;

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

    std::cout << pvss.cl_hsmqk_;

    vector<unique_ptr<const SecretKey>> sks(n);
    vector<unique_ptr<const PublicKey>> pks(n);
    unique_ptr<vector<unique_ptr<const Share>>> shares;
    const Mpz s(1234UL);

    for(size_t i = 0; i < n; i++) 
    {
        sks[i] = pvss.keyGen(randgen);
        pks[i] = pvss.keyGen(*sks[i]);
        unique_ptr<NizkPoK_DL> pf = pvss.keyGen(randgen, *pks[i], *sks[i]);
        
        if(!pvss.verifyKey(*pks[i], move(pf)))
            return EXIT_FAILURE;
    }

    shares = pvss.dist(randgen, s);
    pvss.dist(randgen, pks, *shares);

    return EXIT_SUCCESS;
}