#include "sss.hpp"

using namespace SSS_;

SSS::SSS(RandGen &randgen, const size_t k, const size_t n, const Mpz &q)
    : randgen_(randgen), k_(k), n_(n), q_(q) 
{}

void SSS::shareSecret(const Mpz & s, std::vector<Mpz>& shares) const
{
    std::vector<Mpz> coefficients(degree());

    generatePolynomial(s, coefficients);

    for(size_t i = 0; i < parties(); i++)
            evaluatePolynomial(i + 1, coefficients, shares[i]);
}

const Mpz & SSS::reconstructSecret(std::vector<Mpz>& shares, Mpz & s) const 
{
    if (shares.size() < degree())
        throw std::invalid_argument ("Too few shares to reconstruct secret.");

    std::vector<Mpz> lagrangeWeights(shares.size());
    Mpz temp;

    for (size_t j = 0; j < shares.size(); j++)
    {
        lagrangeWeights[j] = 1UL;

        for(size_t m = 0; m < shares.size(); m++)
        {
            if(m != j) {
                Mpz denum((m + 1) - (j + 1));
                Mpz::mod_inverse(temp, denum, q_);
                Mpz::mul(temp, Mpz(m + 1), temp);
                Mpz::mod(temp, temp, q_);

                Mpz::mul(lagrangeWeights[m], lagrangeWeights[m], temp);
                Mpz::mod(lagrangeWeights[m], lagrangeWeights[m], q_);

                // Mpz::sub(temp, shares[m], shares[j]);
                // Mpz::mul(lagrangeWeights[m], shares[m], temp);
                // Mpz::mod_inverse(lagrangeWeights[m], lagrangeWeights[m], q_);
            }
        }

        Mpz::mul(temp, lagrangeWeights[j], shares[j]);
        Mpz::add(s, s, temp);
        Mpz::mod(s, s, q_);
    }
}

void SSS::generatePolynomial(const Mpz & s, std::vector<Mpz>& coefficients) const
{
    //set a_0 to the secret
    coefficients[0] = s;

    //sample [a_1 ... a_k-1] values and shift a_i's from [0 ... q_ - 1] to [1 ... q]
    for (size_t i = 1; i < degree(); i++)
        coefficients[i] = randgen_.random_mpz(q_); 
}

void SSS::evaluatePolynomial(size_t x, const std::vector<Mpz>& coefficients, Mpz & share) const 
{
    Mpz temp;
    share = coefficients[0];

    //evaluate polynomial for degree [1... k - 1]
    for (size_t i = 1; i < degree(); i++)
    {
        Mpz::pow_mod(temp, Mpz(x), Mpz(i), q_);
        Mpz::mul(temp, temp, coefficients[i]);
        Mpz::add(share, share, temp);
    }

    Mpz::mod(share, share, q_);
}

const size_t & SSS::degree() const {
    return k_;
}

const size_t & SSS::parties() const {
    return n_;
}