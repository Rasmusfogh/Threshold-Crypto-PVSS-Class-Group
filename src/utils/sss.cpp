#include "sss.hpp"

using namespace SSS_;
using namespace std;

SSS::SSS(RandGen &randgen, const size_t& k, const size_t& n, const Mpz &q)
    : randgen_(randgen), k_(k), n_(n), q_(q) 
{}

unique_ptr<vector<unique_ptr<const Share>>> SSS::shareSecret(const Mpz & s) const
{
    vector<Mpz> coefficients(degree());

    unique_ptr<vector<unique_ptr<const Share>>> shares(new vector<unique_ptr<const Share>>(parties()));

    generatePolynomial(s, coefficients);

    for(size_t i = 0; i < parties(); i++)
        (*shares)[i] = evaluatePolynomial(i + 1, coefficients);    

    return shares;
}

void SSS::reconstructSecret(vector<unique_ptr<const Share>>&shares, Mpz & s) const 
{
    if (shares.size() < degree())
        throw std::invalid_argument ("Too few shares to reconstruct secret.");

    for (size_t j = 0; j < degree(); j++)
    {
        Mpz numerator(1UL);
        Mpz denominator(1UL);

        Mpz xj(shares[j]->x());

        for(size_t m = 0; m < degree(); m++)
        {
            if (m == j) continue;

            Mpz xm(shares[m]->x());

            Mpz::mul(numerator, numerator, xm);
            Mpz::sub(xm, xm, xj);
            Mpz::mul(denominator, denominator, xm);
        }

        Mpz::mod_inverse(denominator, denominator, q_);
        Mpz::mul(numerator, numerator, denominator);
        Mpz::mul(numerator, numerator, shares[j]->y());
        Mpz::add(s, s, numerator);
    }

    Mpz::mod(s, s, q_);
}

void SSS::generatePolynomial(const Mpz & s, vector<Mpz>& coefficients) const
{
    if(coefficients.size() < degree())
        throw std::invalid_argument ("Too few shares to reconstruct secret.");

    //set a_0 to the secret
    coefficients[0] = s;

    for (size_t i = 1; i < degree(); i++)
        coefficients[i] = randgen_.random_mpz(q_); 
}

unique_ptr<const Share> SSS::evaluatePolynomial(size_t x, const vector<Mpz>& coefficients) const 
{
    Mpz temp;
    unique_ptr<Share> share(new Share);
    share->first = x;
    share->second = coefficients[0];

    //evaluate polynomial for degree [1... k - 1]
    for (size_t i = 1; i < degree(); i++)
    {
        Mpz::pow_mod(temp, Mpz(x), Mpz(i), q_);
        Mpz::mul(temp, temp, coefficients[i]);
        Mpz::add(share->second, share->second, temp);
    }

    Mpz::mod(share->second, share->second, q_);
    return share;
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

