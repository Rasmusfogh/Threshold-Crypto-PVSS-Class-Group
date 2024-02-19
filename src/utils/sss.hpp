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
        size_t k_; //degree / threshold
        size_t n_; //number of parties
        Mpz q_; //modulo

        SSS(RandGen &randgen, const size_t t, const size_t n, const Mpz&q);
        const std::vector<Mpz> & shareSecret(const Mpz& s) const;
        const Mpz & reconstructSecret(const std::vector<Mpz>& shares) const;

        private:
        void generatePolynomial(const Mpz & s, std::vector<Mpz>& coefficients) const;
        void evaluatePolynomial(size_t x, const std::vector<Mpz>& coefficients, Mpz & share) const;
        const size_t & degree() const;
        const size_t & parties() const;
    };
}

#endif