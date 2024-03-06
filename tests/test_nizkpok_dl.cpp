#include <string>
#include <iostream>
#include <chrono>
#include "../src/qclpvss.hpp"

using namespace BICYCL;
using namespace QCLPVSS_;
using namespace std;

using std::string;

int main (int argc, char *argv[])
{
    Mpz seed;
    size_t qsize = 0;
    size_t k = 1;
    SecLevel seclevel(112);
    RandGen randgen;

    bool compact_variant = false; /* by default the compact variant is not used */

    auto T = std::chrono::system_clock::now();
    seed = static_cast<unsigned long>(T.time_since_epoch().count());

    /* */
    std::cout << "# Using seed = " << seed << std::endl;
    randgen.set_seed (seed);

    Mpz q(randgen.random_prime(113));

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

    size_t n(8);
    size_t t(5);

    CL_HSMqk cl_hsm (q, k, seclevel, randgen, compact_variant);
    SecretKey sk(cl_hsm, randgen);
    PublicKey pk(cl_hsm, sk);

    NizkPoK_DL pf(H, randgen, cl_hsm, pk, sk);

    if(pf.verify(randgen ,pk))
        return EXIT_SUCCESS;

    return EXIT_FAILURE;
}