#include <qclpvss_ext.hpp>

using namespace QCLPVSS_;

QCLPVSS_ext::QCLPVSS_ext(SecLevel& seclevel, HashAlgo& hash, RandGen& rand,
    Mpz &q, const size_t k, const size_t n, const size_t t) 
    : QCLPVSS(seclevel, hash, rand, q, k, n, t) {}

unique_ptr<EncSharesExt> QCLPVSS_ext::share(vector<unique_ptr<const PublicKey>>&, 
                                            vector<unique_ptr<const Share>>&) const
{
    Mpz s = (this->randgen_.random_mpz(this->q_));
    unique_ptr<vector<unique_ptr<const Share>>> shares = this->dist(s);

    //unique_ptr<Nizk_SH_ext> s(new Nizk_SH_ext(H, randgen,  ));


}