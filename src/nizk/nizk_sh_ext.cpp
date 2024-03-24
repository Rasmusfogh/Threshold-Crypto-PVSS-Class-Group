#include <nizk_sh_ext.hpp>

using namespace NIZK;

Nizk_SH_ext::Nizk_SH_ext(HashAlgo& hash, RandGen& rand, const CL_HSMqk& cl, const ECGroup& ec_group, 
    const size_t& n, const size_t& t, const Mpz& q, const vector<unique_ptr<Mpz>>& Vis)
    : Nizk_SH_base(hash, rand, cl, q, n, t, Vis), ec_group_(ec_group)
{ }

void Nizk_SH_ext::prove(const pair<vector<unique_ptr<const Share>>&, Mpz>& w, 
    const vector<unique_ptr<const PublicKey>>& pks, const vector<QFI>& Bs,
    const vector<Mpz>& Ds, const QFI& R)
{
    initRandomOracle(pks, Bs, Ds, R, cl_.h());

    vector<Mpz> coeffs(t_);
    generateCoefficients(coeffs);

    QFI U, V;
    computeUV(U, V, pks, Bs, coeffs);

    Mpz d(0L), d_temp;
    QFI B, B_temp;
    Mpz D(1UL), D_temp;
    QFI M, M_temp;
    for(size_t i = 0; i < t_ + 1; i++)
    {
        Mpz e(queryRandomOracle(q_));

        //compute d
        Mpz::mul(d_temp, e, w.first[i]->y());
        Mpz::add(d, d, d_temp);

        //compute B
        cl_.Cl_Delta().nupow(B_temp, Bs[i], e);
        cl_.Cl_Delta().nucomp(B, B, B_temp);

        //compute D
        Mpz::pow_mod(D_temp, Ds[i], e, q_);
        Mpz::mul(D, D, D_temp);

        //compute M
        pks[i]->exponentiation(cl_, M_temp, e);
        cl_.Cl_Delta().nucomp(M, M, M_temp);
    }

    Mpz::mod(d, d, q_);
    Mpz::mod(D, D, q_); //mod ??

    pair<Mpz, Mpz> witness(w.second, d);

    pf_ = unique_ptr<Nizk_DLEQ_mix> (new Nizk_DLEQ_mix(hash_, rand_, cl_, ec_group_));
    pf_->prove(witness, U, M, R, V, B, D);
}

bool Nizk_SH_ext::verify(const vector<unique_ptr<const PublicKey>>& pks, const vector<QFI>& Bs, 
    const vector<Mpz>& Ds, const QFI& R) const
{
    initRandomOracle(pks, Bs, Ds, R, cl_.h());

    vector<Mpz> coeffs(t_);
    generateCoefficients(coeffs);

    QFI U, V;
    computeUV(U, V, pks, Bs, coeffs);

    QFI B, B_temp;
    Mpz D(1UL), D_temp;
    QFI M, M_temp;
    for(size_t i = 0; i < t_ + 1; i++)
    {
        Mpz e(queryRandomOracle(q_));

        //compute B
        cl_.Cl_Delta().nupow(B_temp, Bs[i], e);
        cl_.Cl_Delta().nucomp(B, B, B_temp);

        //compute D
        Mpz::pow_mod(D_temp, Ds[i], e, q_);
        Mpz::mul(D, D, D_temp);

        //compute M
        pks[i]->exponentiation(cl_, M_temp, e);
        cl_.Cl_Delta().nucomp(M, M, M_temp);
    }

    Mpz::mod(D, D, q_); //mod ??

    return pf_->verify(U, M, R, V, B, D);
}
