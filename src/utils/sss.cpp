#include "sss.hpp"

using namespace SSS_;
using namespace std;

SSS::SSS(RandGen& randgen) : randgen_(randgen) {}

unique_ptr<vector<unique_ptr<const Share>>> SSS::shareSecret(const Mpz& s,
    const size_t k, const size_t n, const Mpz& mod) const {
    vector<Mpz> coefficients;
    coefficients.reserve(k);

    unique_ptr<vector<unique_ptr<const Share>>> shares(
        new vector<unique_ptr<const Share>>());
    shares->reserve(n);

    generatePolynomial(s, coefficients, k, n, mod);

    for (size_t i = 0; i < n; i++)
        shares->emplace_back(evaluatePolynomial(i + 1, coefficients, k, mod));

    return shares;
}

unique_ptr<const Mpz> SSS::reconstructSecret(
    vector<unique_ptr<const Share>>& shares, const size_t k,
    const Mpz& mod) const {
    if (shares.size() < k)
        throw std::invalid_argument("Too few shares to reconstruct secret.");

    unique_ptr<Mpz> s(new Mpz);

    for (size_t j = 0; j < k; j++) {
        Mpz numerator(1UL);
        Mpz denominator(1UL);

        Mpz xj(shares[j]->x());

        for (size_t m = 0; m < k; m++) {
            if (m == j)
                continue;

            Mpz xm(shares[m]->x());

            Mpz::mul(numerator, numerator, xm);
            Mpz::sub(xm, xm, xj);
            Mpz::mul(denominator, denominator, xm);
        }

        Mpz::mod_inverse(denominator, denominator, mod);
        Mpz::mul(numerator, numerator, denominator);
        Mpz::addmul(*s, numerator, shares[j]->y());
    }

    Mpz::mod(*s, *s, mod);

    return s;
}

void SSS::generatePolynomial(const Mpz& s, vector<Mpz>& coefficients,
    const size_t k, const size_t n, const Mpz& mod) const {
    if (k > n)
        throw std::invalid_argument("Too few shares to reconstruct secret.");

    // set a_0 to the secret
    coefficients.push_back(s);

    for (size_t i = 0; i < k; i++)
        coefficients.emplace_back(randgen_.random_mpz(mod));
}

unique_ptr<const Share> SSS::evaluatePolynomial(size_t x,
    const vector<Mpz>& coefficients, const size_t k, const Mpz& mod) const {
    Mpz temp;
    unique_ptr<Share> share(new Share);
    share->first = x;
    share->second = coefficients[0];

    // evaluate polynomial for degree [1... k - 1]
    for (size_t i = 1; i <= k; i++) {
        Mpz::pow_mod(temp, Mpz(x), Mpz(i), mod);
        Mpz::addmul(share->second, temp, coefficients[i]);
    }

    Mpz::mod(share->second, share->second, mod);
    return share;
}

Share::Share(unsigned long x, const Mpz& y) : pair(x, y) {}

Share::Share() : pair(0, Mpz(0UL)) {}

const unsigned long Share::x() const {
    return this->first;
}

const Mpz& Share::y() const {
    return this->second;
}
