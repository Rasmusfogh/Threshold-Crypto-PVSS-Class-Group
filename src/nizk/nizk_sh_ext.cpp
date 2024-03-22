#include <nizk_sh_ext.hpp>

using namespace NIZK;

Nizk_SH_ext::Nizk_SH_ext(HashAlgo& hash, RandGen& rand, const CL_HSMqk& cl, 
    const size_t& n, const size_t& t, const Mpz& q, const vector<unique_ptr<Mpz>>& Vis)
    : Nizk_SH_base(hash, rand, cl, q, n, t, Vis)
{ }

void Nizk_SH_ext::prove(const pair<vector<unique_ptr<const Share>>, Mpz>& w, 
    const vector<unique_ptr<const PublicKey>>& pks, const vector<QFI>& Bs, const vector<Mpz>& Ds, const QFI& R)
{
    initRandomOracle(pks, Bs, Ds, R, cl_.h());

    vector<Mpz> coeffs(t_);
    generateCoefficients(coeffs);

    QFI U, V;
    computeUV(U, V, pks, Bs, coeffs);

    Mpz d, d_temp;
    QFI B, B_temp;
    for(size_t i = 0; i < degree_; i++)
    {
        //compute d
        Mpz e(queryRandomOracle(q_));
        Mpz::mul(d_temp, e, w.first[i]->y());
        Mpz::add(d, d, d_temp);

        //compute B
        cl_.Cl_Delta().nupow(B_temp, Bs[i], e);
        cl_.Cl_Delta().nucomp(B, B, B_temp);
    }

    Mpz::mod(d, d, q_); //Mod ??
}

bool Nizk_SH_ext::verify(const vector<unique_ptr<const PublicKey>>& pks, const vector<QFI>& Bs, 
    const vector<Mpz>& Ds, const QFI& R) const
{

}
