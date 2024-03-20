#ifndef EC_HPP__
#define EC_HPP__

#include <secp256k1.h>
#include "../../include/bicycl/bicycl.hpp"

using namespace BICYCL;

namespace EC
{
    class Secp256k1
    {
        private:
            secp256k1_context* ctx;

        public:
            Secp256k1();
            const Mpz randomPoint() const;
            const Mpz exponent(const Mpz& e) const;
            ~Secp256k1();
    };
}

#endif