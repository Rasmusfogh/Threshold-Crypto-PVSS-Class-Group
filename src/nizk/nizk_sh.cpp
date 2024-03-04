#include "nizk_sh.hpp"

using namespace NIZK;

Nizk_SH::Nizk_SH(HashAlgo &hash, RandGen &randgen, const CL_HSMqk &cl,
    vector<unique_ptr<const PublicKey>>& pks, const vector<unique_ptr<QFI>>& Bs, const QFI& R, 
    const size_t& n, const size_t& t, const Mpz& q, const Mpz& r, const vector<unique_ptr<Mpz>>& Vis) 
    : h_(hash), rand_(randgen), q_(q), n_(n), t_(t), degree_(n - t - 1 - 1), CL_(cl)
{
    Mpz seed;
    //Not sure if correct way to pass f
    initSeed(seed, pks, Bs, R, cl.h(), cl.power_of_f(Mpz(1UL)));

    QFI U, V;
    computeUV(U, V, Vis, pks, Bs, seed);

    pf_ = unique_ptr<Nizk_DLEQ> (new Nizk_DLEQ(hash, randgen, cl, U, R, V, r));
}

bool Nizk_SH::verify(vector<unique_ptr<const PublicKey>>& pks, const vector<unique_ptr<QFI>>& Bs, 
    const QFI& R, const vector<unique_ptr<Mpz>>& Vis)
{
    Mpz seed;
    initSeed(seed, pks, Bs, R, CL_.h(), CL_.power_of_f(Mpz(1UL)));

    QFI U, V;
    computeUV(U, V, Vis, pks, Bs, seed);

    return pf_->verify(U, R, V);
}

void Nizk_SH::initSeed(Mpz& seed, vector<unique_ptr<const PublicKey>>& pks, 
        const vector<unique_ptr<QFI>>& Bs, const QFI& R, const QFI&h, const QFI& f) const
{
    seed = Mpz(h_(pks, R, Bs, h, f));
}

void Nizk_SH::computeUV(QFI& U_ref, QFI& V_ref, const vector<unique_ptr<Mpz>>& Vis, 
        vector<unique_ptr<const PublicKey>>& pks, const vector<unique_ptr<QFI>>& Bs, const Mpz& seed) const
{
    QFI exp;
    Mpz temp, poly_eval;

    for (size_t i = 0; i < n_; i++)
    {
        rand_.set_seed(seed); //set seed to generate same coefficients every n times
        poly_eval = rand_.random_mpz(q_); // coefficient 0 aka secret

        //Evaluate polynomial m*
        for(size_t j = 1; j < degree_; j++)
        {
            Mpz::pow_mod(temp, Mpz(i + 1), Mpz(j), q_); 
            Mpz::mul(temp, temp, rand_.random_mpz(q_)); //remaining coefficients
            Mpz::add(poly_eval, poly_eval, temp);
        }

        Mpz::mod(poly_eval, poly_eval, q_);

    
        //compute wi = temp
        Mpz::mul(temp, poly_eval, *Vis[i]);
        Mpz::mod(temp, temp, q_);

        //compute wi' = temp
        Mpz ci(rand_.random_mpz(q_)); //ci using RNG
        Mpz::addmul(temp, ci, q_); 
        Mpz::mod(temp, temp, q_);

        //compute U
        (*pks[i]).exponentiation(CL_, exp, temp);
        CL_.Cl_Delta().nucomp(U_ref, U_ref, exp);

        //compute V
        CL_.Cl_Delta().nupow(exp, (*Bs[i]), temp);
        CL_.Cl_Delta().nucomp(V_ref, V_ref, exp);
    }
}

template<>
void OpenSSL::HashAlgo::hash(const vector<unique_ptr<QFI>> &v)
{
    for(size_t i = 0; i < v.size(); i++)
        hash (*v[i]);
}

template<>
void OpenSSL::HashAlgo::hash(const vector<unique_ptr<const PublicKey>>& v)
{
    for(size_t i = 0; i < v.size(); i++)
        hash (v[i]->get());
}