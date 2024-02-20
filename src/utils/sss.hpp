#ifndef SSS__
#define SSS__

#include <iostream>
#include "bicycl.hpp"

using namespace BICYCL;
using namespace std;

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
        void shareSecret(const Mpz& s, vector<tuple<unsigned long, Mpz>>& shares) const;
        const Mpz & reconstructSecret(vector<tuple<unsigned long, Mpz>>& shares, Mpz &s) const;

        private:
        void generatePolynomial(const Mpz & s, vector<Mpz>& coefficients) const;
        void evaluatePolynomial(size_t x, const vector<Mpz>& coefficients, tuple<unsigned long, Mpz>& share) const;
        const size_t & degree() const;
        const size_t & parties() const;
    };
}

#endif