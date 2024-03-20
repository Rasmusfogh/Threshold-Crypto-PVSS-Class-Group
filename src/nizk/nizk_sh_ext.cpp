#include <nizk_sh_ext.hpp>

using namespace NIZK;

Nizk_SH_ext::Nizk_SH_ext(HashAlgo& hash, RandGen& rand, const CL_HSMqk& cl, vector<unique_ptr<const PublicKey>>& pks, 
    const vector<QFI>& Bs, const QFI& R, const vector<Mpz>& Ds, const size_t& n, const size_t& t, 
    const Mpz& q, const vector<unique_ptr<Mpz>>& Vis)
    : Nizk_SH_base(hash, rand, cl, q, n, t, Vis)
{
    initRandomOracle(pks, Bs, Ds, R, cl.h(), cl.power_of_f(Mpz(1UL)));

    vector<Mpz> coeffs(t);
    generateCoefficients(coeffs);

    QFI U, V;
    computeUV(U, V, pks, Bs, coeffs);
}

bool Nizk_SH_ext::verify(const vector<unique_ptr<const PublicKey>>&, const vector<QFI>& Bs, 
    const vector<QFI>& Ds, const QFI& R) const
{

}