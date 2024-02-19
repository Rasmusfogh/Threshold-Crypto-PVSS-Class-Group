#ifndef SSS__
#define SSS__

#include <iostream>
#include "bicycl.hpp"

using namespace BICYCL;

namespace SSS_
{
    class SSS 
    {
        protected:
        RandGen& randgen_;

        public:
        const size_t k_; //degree / threshold
        const size_t n_; //number of parties
        const Mpz q_; //modulo

        SSS(RandGen &randgen, const size_t t, const size_t n, const Mpz&q);
        void shareSecret(const Mpz& s, std::vector<Mpz>& shares) const;
        const Mpz & reconstructSecret(std::vector<Mpz>& shares, Mpz &s) const;

        private:
        void generatePolynomial(const Mpz & s, std::vector<Mpz>& coefficients) const;
        void evaluatePolynomial(size_t x, const std::vector<Mpz>& coefficients, Mpz & share) const;
        const size_t & degree() const;
        const size_t & parties() const;
    };
}

#endif