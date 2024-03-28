#include "qclpvss.hpp"

using namespace QCLPVSS_;
using namespace NIZK;
using namespace SSS_;
using namespace UTILS;
using namespace BICYCL;
using namespace OpenSSL;
using namespace DATATYPE;

QCLPVSS::QCLPVSS (SecLevel& seclevel, HashAlgo &hash, RandGen& randgen, Mpz &q, const size_t k, 
  const size_t n, const size_t t) :
      CL_(CL_HSMqk (q, k, seclevel, randgen, false)),
      sss_(SSS(randgen, t, n, q)),
      seclevel_(seclevel),
      randgen_(randgen),
      hash_(hash),
      k_(k),
      n_(n),
      t_(t),
      q_(q)
{
  /* Checks */
  if (Mpz(n + k) > q)
      throw std::invalid_argument ("n + k must be less than or equal to q");
  if (t_ + k > n_)
      throw std::invalid_argument ("k + t must be less than or equal to n");    

    computeFixedPolyPoints(Vis_, n_, q_);
}

unique_ptr<const SecretKey> QCLPVSS::keyGen(RandGen &randgen) const
{
    return unique_ptr<const SecretKey>(new SecretKey(CL_, randgen));
}

unique_ptr<const PublicKey> QCLPVSS::keyGen(const SecretKey& sk) const
{
    return unique_ptr<const PublicKey>(new PublicKey(CL_, sk));
}

unique_ptr<NizkPoK_DL> QCLPVSS::keyGen(const PublicKey& pk, const SecretKey& sk) const
{
    unique_ptr<NizkPoK_DL> pf(new NizkPoK_DL(hash_, randgen_, CL_));
    pf->prove(sk, pk);
    return pf;
}

bool QCLPVSS::verifyKey(const PublicKey& pk,  const NizkPoK_DL& pf) const 
{
    return pf.verify(pk);
}

unique_ptr<EncShares> QCLPVSS::dist(const Mpz &s, vector<unique_ptr<const PublicKey>>& pks) const 
{
    unique_ptr<vector<unique_ptr<const Share>>> shares = createShares(s);
    unique_ptr<EncShares> enc_shares = computeEncryptedShares(*shares, pks);
    computeSHNizk(pks, *enc_shares);
    return enc_shares;
}


bool QCLPVSS::verifySharing(const EncShares& sh, vector<unique_ptr<const PublicKey>>& pks) const 
{
  return sh.pf->verify(pks, *sh.Bs, sh.R);
}

unique_ptr<DecShare> QCLPVSS::decShare(const PublicKey& pk, const SecretKey& sk, const QFI& R, const QFI& B, size_t i) const 
{
    QFI fi, Mi;

    unique_ptr<DecShare> dec_share (new DecShare());

    CL_.Cl_Delta().nupow(fi, R, sk);
    CL_.Cl_Delta().nucompinv(fi, B, fi);
    CL_.Cl_Delta().nucompinv(Mi, B, fi);

    //return Ai on the form of a share <i, Ai>
    dec_share->sh = unique_ptr<const Share>(new Share(i + 1, Mpz(CL_.dlog_in_F(fi)))); 
    dec_share->pf = unique_ptr<Nizk_DLEQ>(new Nizk_DLEQ(hash_, randgen_, CL_));
    dec_share->pf->prove(sk, CL_.h(), R, pk.get(), Mi);
    return dec_share;
}

unique_ptr<const Mpz> QCLPVSS::rec(vector<unique_ptr<const Share>>& Ais) const 
{
  // |T| < t + k
  if (Ais.size() < t_ + k_)
    return nullptr;
  
  return sss_.reconstructSecret(Ais);
}

bool QCLPVSS::verifyDec(const DecShare& dec_share, const PublicKey& pki, const QFI& R, const QFI& B) const 
{
  QFI Mi(CL_.power_of_f(dec_share.sh->y()));
  CL_.Cl_Delta().nucompinv(Mi, B , Mi);

  return dec_share.pf->verify(CL_.h(), R, pki.get(), Mi);
}

unique_ptr<vector<unique_ptr<const Share>>> QCLPVSS::createShares(const Mpz &s) const 
{
    return sss_.shareSecret(s);
}

unique_ptr<EncShares> QCLPVSS::computeEncryptedShares(vector<unique_ptr<const Share>>& shares,
  vector<unique_ptr<const PublicKey>>& pks) const
{
    QFI f, pkr;
    unique_ptr<EncShares> enc_sh (new EncShares(n_));

    enc_sh->r = randgen_.random_mpz(CL_.encrypt_randomness_bound());

    //Compute R
    CL_.power_of_h(enc_sh->R, enc_sh->r);

    //Compute B_i's
    for(size_t i = 0; i < n_; i++)
    {
        //f^p(a_i)
        f = CL_.power_of_f(shares[i]->y());
        //(pk_i)^r
        pks[i]->exponentiation(CL_, pkr, enc_sh->r);
        // B_i = (pk_i)^r * f^p(a_i)

        CL_.Cl_Delta().nucomp(*enc_sh->Bs->at(i), pkr, f);
    }

    return enc_sh;
}

void QCLPVSS::computeSHNizk(vector<unique_ptr<const PublicKey>>& pks, EncShares& enc_shares) const
{
    enc_shares.pf = unique_ptr<Nizk_SH>(new Nizk_SH
        (hash_, randgen_, CL_, n_, t_, q_, Vis_));

    enc_shares.pf->prove(enc_shares.r, pks, *enc_shares.Bs, enc_shares.R); 
}

void QCLPVSS::computeFixedPolyPoints(vector<unique_ptr<Mpz>>& vis, const size_t& n, const Mpz& q)
{
    vis.reserve(n_);
    generate_n(back_inserter(vis), n_, [] {return unique_ptr<Mpz>(new Mpz(1UL)); });

    for(size_t i = 0; i < n_; i++)
    {
      for(size_t j = 0; j < n_; j++)
      {
        if(i == j) continue;

        //Add one to both i and j as alphas are [1...n_]
        Mpz sub((signed long)((i + 1) - (j + 1)));
        Mpz::mul(*vis[i], *vis[i], sub);
      }

      Mpz::mod_inverse(*vis[i], *vis[i], q_);
    }
}