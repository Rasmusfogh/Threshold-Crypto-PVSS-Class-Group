#include <qclpvss_ext.hpp>

using namespace QCLPVSS_;

QCLPVSS_ext::QCLPVSS_ext(SecLevel& seclevel, HashAlgo& hash, RandGen& rand, 
    const ECGroup& ec_group, Mpz &q, const size_t k, const size_t n, const size_t t) 
    :   QCLPVSS(seclevel, hash, rand, q, k, n, t), 
        ec_group_(ec_group) {}

unique_ptr<EncSharesExt> QCLPVSS_ext::share(vector<unique_ptr<const PublicKey>>& pks) const
{
    Mpz s = (randgen_.random_mpz(q_));
    unique_ptr<vector<unique_ptr<const Share>>> shares = createShares(s);
    unique_ptr<EncShares> enc_shares = computeEncryptedShares(*shares, pks);

    unique_ptr<EncSharesExt> enc_shares_ext (new EncSharesExt(n_));

    cout << ec_group_ << endl;

    for(size_t i = 0; i < n_; i++)
    {
        BN bn((*shares)[i]->second);
        enc_shares_ext->Ds_[i] = unique_ptr<ECPoint> (new ECPoint(ec_group_, bn));
    }

    enc_shares_ext->r_ = enc_shares->r;
    enc_shares_ext->R_ = enc_shares->R;
    enc_shares_ext->Bs_ = enc_shares->Bs;
    enc_shares_ext->pf_ = unique_ptr<Nizk_SH_ext>(
        new Nizk_SH_ext(hash_, randgen_, CL_, ec_group_, n_, t_, q_, Vis_));

    pair<vector<unique_ptr<const Share>>&, Mpz> witness(*shares, enc_shares_ext->r_);

    enc_shares_ext->pf_->prove(witness, pks, enc_shares_ext->Bs_, enc_shares_ext->Ds_, enc_shares->R);

    return enc_shares_ext;
}