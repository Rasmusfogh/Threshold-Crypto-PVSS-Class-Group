#include <nizk_sh_ext.hpp>

using namespace NIZK;

Nizk_SH_ext::Nizk_SH_ext(HashAlgo& hash, RandGen& randgen, const CL_HSMqk& cl, 
    vector<unique_ptr<const PublicKey>>& pks, const vector<QFI>& Bs, const QFI& R, 
    const vector<Mpz>& Ds, const size_t& n, const size_t& t, const Mpz& q, const vector<unique_ptr<Mpz>>& Vis)
    : h_(hash), rand_(randgen), q_(q), n_(n), t_(t), degree_(n - t - 1 - 1), CL_(cl)
{
    Mpz seed;
    //initSeed(seed, pks, Bs, R, Ds, cl.h(), cl.power_of_f(Mpz(1UL)));


}

template <typename... Args>
void Nizk_SH_ext::initSeed(Mpz& seed, const Args & ...args)
{
    seed = Mpz(h_(args));
}