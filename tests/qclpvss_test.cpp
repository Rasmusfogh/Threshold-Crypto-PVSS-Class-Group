#include <string>
#include <iostream>
#include <chrono>
#include "../src/qclpvss.hpp"

using namespace BICYCL;
using namespace QCLPVSS_;

using std::string;

void usage (const string &argv0)
{
  std::cout << "Usage: " << argv0
            << " -seclevel <integer> [-compact-variant] [-q <q>] "
            << "[-qsize <qsize>] [-seed <s>]" << std::endl << std::endl
            << "Parameters:" << std::endl
            << "  -seclevel <integer> target security level (";
  size_t i = 0;
  for (const BICYCL::SecLevel v: BICYCL::SecLevel::All())
  {
    if (i > 0 && i+1 < BICYCL::SecLevel::All().size())
      std::cout << ", ";
    else if (i+1 == BICYCL::SecLevel::All().size())
      std::cout << " or ";
    std::cout << v;
    i++;
  }
  std::cout << ")" << std::endl
            << "  -q <q>              prime q" << std::endl
            << "  -qsize <qsize>      the size of theprime q, if q is not given"
            << std::endl
            << "  -k <k>              positive integer k (default: 1)"
            << std::endl
            << "  -seed <s>           seed for random generator" << std::endl
            << "  -compact-variant    use the compact variant" << std::endl;
}

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

    size_t n(8);
    size_t t(5);

    QCLPVSS pvss(seclevel, H, randgen, randgen, q, k, n, t, compact_variant);

    std::cout << pvss.cl_hsmqk_;

        return 0;
}