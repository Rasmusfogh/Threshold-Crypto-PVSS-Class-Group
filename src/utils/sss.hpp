#ifndef SSS__
#define SSS__

#include "bicycl.hpp"
#include <iostream>
#include <memory>

using namespace BICYCL;
using namespace std;

namespace SSS_ {
    class Share : public pair<unsigned long, Mpz> {
      public:
        Share();
        Share(unsigned long x, const Mpz& y);
        const unsigned long x() const;
        const Mpz& y() const;
    };

    class SSS {
      protected:
        RandGen& randgen_;

      public:
        const size_t k_;    // degree / threshold
        const size_t n_;    // number of parties
        const Mpz& q_;      // modulo

        SSS(RandGen& randgen, const size_t k, const size_t n, const Mpz& q);
        unique_ptr<vector<unique_ptr<const Share>>> shareSecret(
            const Mpz& secret) const;
        unique_ptr<const Mpz> reconstructSecret(
            vector<unique_ptr<const Share>>& shares) const;

      private:
        void generatePolynomial(const Mpz& s, vector<Mpz>& coefficients) const;
        unique_ptr<const Share> evaluatePolynomial(size_t x,
            const vector<Mpz>& coefficients) const;
    };
}    // namespace SSS_

#endif