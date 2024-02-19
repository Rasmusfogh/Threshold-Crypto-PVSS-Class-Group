#include "sss.hpp"

using namespace SSS_;

SSS::SSS(RandGen &randgen, const size_t k, const size_t n, const Mpz &q)
    : randgen_(randgen), k_(k), n_(n), q_(q) 
{}

const std::vector<Mpz> & SSS::shareSecret(const Mpz & s) const
{
    std::vector<Mpz> coefficients(degree());
    std::vector<Mpz> shares(parties());

    generatePolynomial(s, coefficients);

    for(size_t i = 0; i < parties(); i++)
    {
        if(shares[i].is_zero()) //remove when ensured that mpz on instantiation is 0
        {
            evaluatePolynomial(i + 1, coefficients, shares[i]);
        }
    }

    return shares;
}

const Mpz & SSS::reconstructSecret(const std::vector<Mpz>& shares) const 
{
    if (shares.size() < degree())
        throw std::invalid_argument ("Too few shares to reconstruct secret.");

    std::vector<Mpz> lagrangeWeights(degree());
    Mpz temp, result;

    for (size_t j = 0; j < degree() - 1; j++)
    {
        for(size_t m = 0; m < degree() - 1; m++)
        {
            if(m != j) {
                Mpz::sub(temp, shares[m], shares[j]);
                Mpz::mul(lagrangeWeights[m], lagrangeWeights[m], temp);
                Mpz::mod_inverse(lagrangeWeights[m], lagrangeWeights[m], q_);
            }
        }

        Mpz::mul(temp, lagrangeWeights[j], shares[j]);
        Mpz::add(result, result, temp);
        Mpz::mod(result, result, q_);
    }

    return result;
}

void SSS::generatePolynomial(const Mpz & s, std::vector<Mpz>& coefficients) const
{
    //set a_0 to the secret
    coefficients[0] = s;

    //sample [a_1 ... a_k-1] values and shift a_i's from [0 ... q_ - 1] to [1 ... q]
    for (size_t i = 1; i < degree(); i++)
        Mpz::add(coefficients[i], randgen_.random_mpz(q_), 1UL); 
}

void SSS::evaluatePolynomial(size_t x, const std::vector<Mpz>& coefficients, Mpz & share) const 
{
    Mpz temp;

    //evaluate polynomial for degree [1... k - 1]
    for (size_t i = degree() - 1; i > 0; i++)
    {
        Mpz::pow_mod(temp, Mpz(x), Mpz(i), q_);
        Mpz::mul(temp, temp, coefficients[i]);
        Mpz::add(share, share, temp);
    }

    //Add coefficient[0], being the secret
    Mpz::add(share, share, coefficients[0]);
    Mpz::mod(share, share, q_);
}

const size_t & SSS::degree() const {
    return k_;
}

const size_t & SSS::parties() const {
    return n_;
}