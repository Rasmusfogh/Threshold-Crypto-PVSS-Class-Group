#include "nizk_sh.hpp"

using namespace NIZK;

Nizk_SH::Nizk_SH(HashAlgo &hash, RandGen &randgen, const CL_HSMqk &cl_hsm,
    vector<unique_ptr<const PublicKey>>& pks, const vector<unique_ptr<QFI>>& Bs, const QFI& R, 
    const size_t& n, const size_t& t, const Mpz& q, const Mpz& r, const vector<unique_ptr<Mpz>>& Vis) 
    : h_(hash), rand_(randgen), q_(q), n_(n), t_(t), degree_(n - t - 1 - 1)
{
    //Not sure if correct way to pass f
    initRNG(randgen, pks, Bs, R, cl_hsm.h(), cl_hsm.power_of_f(Mpz(1UL)));

    QFI U, V;
    computeUV(U, V, cl_hsm, Vis, pks, Bs, degree_);

    /** TEST */
    QFI ref, ref2;
    cl_hsm.power_of_h(ref, r);
    if (ref == R)
        cout << "true 1" << endl;
    
    cl_hsm.Cl_Delta().nupow(ref2, U, r);
    if (ref2 == V)
        cout << "true 2" << endl;


    pf_ = unique_ptr<Nizk_DLEQ> (new Nizk_DLEQ(hash, randgen, cl_hsm, U, R, V, r));
}

bool Nizk_SH::verify(const CL_HSMqk& cl_hsm, vector<unique_ptr<const PublicKey>>& pks, 
    const vector<unique_ptr<QFI>>& Bs, const QFI& R, const vector<unique_ptr<Mpz>>& Vis)
{
    initRNG(rand_, pks, Bs, R, cl_hsm.h(), cl_hsm.power_of_f(Mpz(1UL)));

    QFI U, V;
    computeUV(U, V, cl_hsm, Vis, pks, Bs, degree_);

    return pf_->verify(cl_hsm, U, R, V);
}

void Nizk_SH::initRNG(RandGen& randgen, vector<unique_ptr<const PublicKey>>& pks, 
        const vector<unique_ptr<QFI>>& Bs, const QFI& R, const QFI&h, const QFI& f) const
{
    const Mpz seed(h_(pks, R, Bs, h, f));
    randgen.set_seed(seed);
}

void Nizk_SH::computeUV(QFI& U_ref, QFI& V_ref, const CL_HSMqk& cl_hsm, const vector<unique_ptr<Mpz>>& Vis, 
        vector<unique_ptr<const PublicKey>>& pks, const vector<unique_ptr<QFI>>& Bs, size_t degree) const
{
    QFI exp;
    Mpz temp;
    Mpz poly_eval(rand_.random_mpz(q_)); //first coefficient

    for (size_t i = 1; i <= n_; i++)
    {
        //Evaluate polynomial
        for(size_t j = 1; j < degree; j++)
        {
            Mpz::pow_mod(temp, Mpz(i), Mpz(j), q_); 
            Mpz::mul(temp, temp, rand_.random_mpz(q_)); //remainging coefficients
            Mpz::add(poly_eval, poly_eval, temp);
        }

        Mpz::mod(poly_eval, poly_eval, q_);
    
        //compute wi
        Mpz::mul(temp, poly_eval, *Vis[i - 1]);
        Mpz::mod(temp, temp, q_);

        //compute wi'
        Mpz wii(temp);
        Mpz ci(rand_.random_mpz(Mpz(n_))); //ci using RNG
        Mpz::addmul(wii, ci, q_); 
        Mpz::mod(wii, wii, q_);

        //compute U
        (*pks[i - 1]).exponentiation(cl_hsm, exp, wii);
        cl_hsm.Cl_Delta().nucomp(U_ref, U_ref, exp);

        //compute V
        cl_hsm.Cl_Delta().nupow(exp, (*Bs[i - 1]), wii);
        cl_hsm.Cl_Delta().nucomp(V_ref, V_ref, exp);
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