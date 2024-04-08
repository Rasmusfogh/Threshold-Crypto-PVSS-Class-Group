#ifndef SSS__
#define SSS__

#include <bicycl.hpp>
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
        SSS(RandGen& randgen);
        unique_ptr<vector<unique_ptr<const Share>>> shareSecret(
            const Mpz& secret, const size_t k, const size_t n,
            const Mpz& mod) const;
        unique_ptr<const Mpz> reconstructSecret(
            vector<unique_ptr<const Share>>& shares, const size_t k,
            const Mpz& mod) const;

      private:
        void generatePolynomial(const Mpz& s, vector<Mpz>& coefficients,
            const size_t k, const size_t n, const Mpz& mod) const;
        unique_ptr<const Share> evaluatePolynomial(size_t x,
            const vector<Mpz>& coefficients, const size_t k,
            const Mpz& mod) const;
    };
}    // namespace SSS_

#endif