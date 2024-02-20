#ifndef SSS__
#define SSS__

#include <iostream>
#include "bicycl.hpp"

using namespace BICYCL;
using namespace std;

namespace SSS_
{
    class Share : public pair<unsigned long, Mpz>
    {
        public:
        Share();
        Share(unsigned long x, const Mpz& y);
        const unsigned long x() const;
        const Mpz& y() const;
    };

    class SSS 
    {
        protected:
        RandGen& randgen_;

        public:
        const size_t k_; //degree / threshold
        const size_t n_; //number of parties
        const Mpz q_; //modulo

        SSS(RandGen &randgen, const size_t t, const size_t n, const Mpz&q);
        void shareSecret(const Mpz& s, vector<Share>& shares) const;
        const Mpz & reconstructSecret(vector<Share>& shares, Mpz &s) const;

        private:
        void generatePolynomial(const Mpz & s, vector<Mpz>& coefficients) const;
        void evaluatePolynomial(size_t x, const vector<Mpz>& coefficients, Share& share) const;
        const size_t & degree() const;
        const size_t & parties() const;
    };
}

#endif