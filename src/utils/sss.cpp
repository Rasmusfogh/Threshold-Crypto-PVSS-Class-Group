#include "sss.hpp"

using namespace SSS_;
using namespace std;

SSS::SSS(RandGen &randgen, const size_t k, const size_t n, const Mpz &q)
    : randgen_(randgen), k_(k), n_(n), q_(q) 
{}

void SSS::shareSecret(const Mpz & s, vector<Share>& shares) const
{
    vector<Mpz> coefficients(degree());

    generatePolynomial(s, coefficients);

    for(size_t i = 0; i < parties(); i++)
            evaluatePolynomial(i + 1, coefficients, shares[i]);
}

const Mpz & SSS::reconstructSecret(vector<Share>&shares, Mpz & s) const 
{
    if (shares.size() < degree())
        throw std::invalid_argument ("Too few shares to reconstruct secret.");

    for (size_t j = 0; j < shares.size(); j++)
    {
        Mpz numerator(1UL);
        Mpz denominator(1UL);

        Mpz xj(shares[j].x());

        for(size_t m = 0; m < shares.size(); m++)
        {
            if (m == j) continue;

            Mpz xm(shares[m].x());

            Mpz::mul(numerator, numerator, xm);
            Mpz::sub(xm, xm, xj);
            Mpz::mul(denominator, denominator, xm);
        }

        Mpz::mod_inverse(denominator, denominator, q_);
        Mpz::mul(numerator, numerator, denominator);
        Mpz::mul(numerator, numerator, shares[j].y());
        Mpz::add(s, s, numerator);
    }

    Mpz::mod(s, s, q_);
}

void SSS::generatePolynomial(const Mpz & s, vector<Mpz>& coefficients) const
{
    //set a_0 to the secret
    coefficients[0] = s;

    for (size_t i = 1; i < degree(); i++)
        coefficients[i] = randgen_.random_mpz(q_); 
}

void SSS::evaluatePolynomial(size_t x, const vector<Mpz>& coefficients, Share& share) const 
{
    Mpz temp, share_val;
    share.first = x;
    share.second = coefficients[0];

    //evaluate polynomial for degree [1... k - 1]
    for (size_t i = 1; i < degree(); i++)
    {
        Mpz::pow_mod(temp, Mpz(x), Mpz(i), q_);
        Mpz::mul(temp, temp, coefficients[i]);
        Mpz::add(temp, share.y(), temp);
    }

    Mpz::mod(share.second, temp, q_);
}

const size_t & SSS::degree() const {
    return k_;
}

const size_t & SSS::parties() const {
    return n_;
}

Share::Share(unsigned long x, const Mpz& y) :pair(x, y) {}

Share::Share() : pair(0, Mpz(0UL)) {}

const unsigned long Share::x() const {
    return this->first;
}

const Mpz& Share::y() const {
    return this->second;
}
