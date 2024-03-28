#include "sss.hpp"

using namespace SSS_;
using namespace std;

SSS::SSS(RandGen &randgen, const size_t& k, const size_t& n, const Mpz &q)
    : randgen_(randgen), k_(k), n_(n), q_(q) 
{}

unique_ptr<vector<unique_ptr<const Share>>> SSS::shareSecret(const Mpz & s) const
{
    vector<Mpz> coefficients;
    coefficients.reserve(k_);

    unique_ptr<vector<unique_ptr<const Share>>> shares(new vector<unique_ptr<const Share>>());
    shares->reserve(n_);

    generatePolynomial(s, coefficients);

    for(size_t i = 0; i < n_; i++)
        shares->emplace_back(evaluatePolynomial(i + 1, coefficients));

    return shares;
}

unique_ptr<const Mpz> SSS::reconstructSecret(vector<unique_ptr<const Share>>&shares) const 
{
    if (shares.size() < k_)
        throw std::invalid_argument ("Too few shares to reconstruct secret.");

    unique_ptr<Mpz> s (new Mpz);

    for (size_t j = 0; j < k_; j++)
    {
        Mpz numerator(1UL);
        Mpz denominator(1UL);

        Mpz xj(shares[j]->x());

        for(size_t m = 0; m < k_; m++)
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
        Mpz::add(*s, *s, numerator);
    }

    Mpz::mod(*s, *s, q_);

    return s;
}

void SSS::generatePolynomial(const Mpz & s, vector<Mpz>& coefficients) const
{
    if(k_ > n_)
        throw std::invalid_argument ("Too few shares to reconstruct secret.");

    //set a_0 to the secret
    coefficients.push_back(s);

    for (size_t i = 1; i < k_; i++)
        coefficients.emplace_back(randgen_.random_mpz(q_)); 
}

unique_ptr<const Share> SSS::evaluatePolynomial(size_t x, const vector<Mpz>& coefficients) const 
{
    Mpz temp;
    unique_ptr<Share> share(new Share);
    share->first = x;
    share->second = coefficients[0];

    //evaluate polynomial for degree [1... k - 1]
    for (size_t i = 1; i < k_; i++)
    {
        Mpz::pow_mod(temp, Mpz(x), Mpz(i), q_);
        Mpz::mul(temp, temp, coefficients[i]);
        Mpz::add(share->second, share->second, temp);
    }

    Mpz::mod(share->second, share->second, q_);
    return share;
}

Share::Share(unsigned long x, const Mpz& y) :pair(x, y) {}

Share::Share() : pair(0, Mpz(0UL)) {}

const unsigned long Share::x() const {
    return this->first;
}

const Mpz& Share::y() const {
    return this->second;
}

