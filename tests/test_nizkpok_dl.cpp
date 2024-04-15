#include "qclpvss.hpp"
#include <chrono>
#include <iostream>
#include <string>

using namespace BICYCL;
using namespace QCLPVSS_;
using namespace std;

using std::string;

int main(int argc, char* argv[]) {
    Mpz seed;
    size_t qsize = 0;
    size_t k = 1;
    SecLevel seclevel(128);
    RandGen randgen;

    auto T = std::chrono::system_clock::now();
    seed = static_cast<unsigned long>(T.time_since_epoch().count());
    randgen.set_seed(seed);

    Mpz q(randgen.random_prime(256));

    /* */
    std::cout << "# security: " << seclevel << " bits" << std::endl;

    /* q and qsize are mutually exclusive */
    if ((q.sgn() != 0 && qsize != 0) || (q.is_zero() && qsize == 0)) {
        std::cerr << "Error, exactly one of q or qsize must be provided"
                  << std::endl;
        return EXIT_FAILURE;
    }

    /* If q is given, it should be prime */
    if (q.sgn() != 0 && (q.sgn() < 0 || !q.is_prime())) {
        std::cerr << "Error, q must be positive and prime" << std::endl;
        return EXIT_FAILURE;
    }

    OpenSSL::HashAlgo H(seclevel);

    size_t n(10);
    size_t t(5);

    CL_HSMqk cl_hsm(q, k, seclevel, randgen, false);
    SecretKey sk(cl_hsm, randgen);
    PublicKey pk(cl_hsm, sk);

    NizkDL pf(H, randgen, cl_hsm, seclevel);

    pf.prove(sk, pk);

    if (pf.verify(pk))
        return EXIT_SUCCESS;

    return EXIT_FAILURE;
}