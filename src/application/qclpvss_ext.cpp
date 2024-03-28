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

    unique_ptr<EncSharesExt> enc_shares_ext (new EncSharesExt(n_, ec_group_));

    for(size_t i = 0; i < n_; i++)
        ec_group_.scal_mul_gen(*enc_shares_ext->Ds_->at(i), BN((*shares)[i]->second));
    

    enc_shares_ext->r_ = enc_shares->r;
    enc_shares_ext->R_ = enc_shares->R;
    enc_shares_ext->Bs_ = move(enc_shares->Bs);
    enc_shares_ext->pf_ = unique_ptr<Nizk_SH_ext>(
        new Nizk_SH_ext(hash_, randgen_, CL_, ec_group_, n_, t_, q_, Vis_));

    pair<vector<unique_ptr<const Share>>&, Mpz> witness(*shares, enc_shares_ext->r_);

    enc_shares_ext->pf_->prove(witness, pks, *enc_shares_ext->Bs_, *enc_shares_ext->Ds_, enc_shares_ext->R_);

    return enc_shares_ext;
}

unique_ptr<ECPoint> QCLPVSS_ext::generate_sk_share(const vector<unique_ptr<ECPoint>>& Ds) const
{
    //Set R = D[0]
    unique_ptr<ECPoint> R(new ECPoint(ec_group_));

    for(const auto & D : Ds)
        ec_group_.ec_add(*R, *R, *D);
    
    return R;
}

unique_ptr<Mpz> QCLPVSS_ext::compute_sk(const vector<unique_ptr<QFI>>& Bs, 
    const vector<QFI>& Rs, const SecretKey& sk) const
{
    QFI B, R, fi;

    size_t sizeof_Q = Bs.size();
    for(size_t i = 0; i < sizeof_Q; i++)
    {
        this->CL_.Cl_Delta().nucomp(B, B, *Bs[i]);
        this->CL_.Cl_Delta().nucomp(R, R, Rs[i]);
    }

    this->CL_.Cl_Delta().nupow(fi, R, sk);
    this->CL_.Cl_Delta().nucompinv(fi, B, fi);

    return unique_ptr<Mpz>(new Mpz(this->CL_.dlog_in_F(fi)));
}