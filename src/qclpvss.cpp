#include "qclpvss.hpp"

using namespace QCLPVSS_;
using namespace NIZK;
using namespace SSS_;
using namespace UTILS;
using namespace BICYCL;
using namespace OpenSSL;

QCLPVSS::QCLPVSS (SecLevel seclevel, HashAlgo &hash, RandGen& randgen, Mpz &q, const size_t k, 
  const size_t n, const size_t t, bool compact_variant) :
      CL_(CL_HSMqk (q, k, seclevel, randgen, compact_variant)),
      fi_(unique_ptr<QFI>(new QFI())),
      R_(unique_ptr<QFI>(new QFI)),
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

    Bs_.reserve(n_);
    generate_n(back_inserter(Bs_), n_, [] {return unique_ptr<QFI>(new QFI); });

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
  return unique_ptr<NizkPoK_DL>(new NizkPoK_DL(hash_, randgen_, CL_, pk, sk));
}

bool QCLPVSS::verifyKey(const PublicKey& pk,  const NizkPoK_DL& pf) const 
{
  return pf.verify(randgen_, pk);
}

unique_ptr<vector<unique_ptr<const Share>>> QCLPVSS::dist(const Mpz &s) const 
{
  return sss_.shareSecret(s);
}

unique_ptr<Nizk_SH> QCLPVSS::dist(vector<unique_ptr<const PublicKey>>& pks, 
  vector<unique_ptr<const Share>>& shares) const 
{
  QFI f, pkr;

  const Mpz r(randgen_.random_mpz(CL_.encrypt_randomness_bound()));

  //Compute R
  CL_.power_of_h(*R_, r);

  //Compute B_i's
  for(size_t i = 0; i < n_; i++)
  {
    //f^p(a_i)
    f = CL_.power_of_f(shares[i]->y());
    //(pk_i)^r
    pks[i]->exponentiation(CL_, pkr, r);
    // B_i = (pk_i)^r * f^p(a_i)
    CL_.Cl_Delta().nucomp(*Bs_[i], pkr, f);
  }

  return unique_ptr<Nizk_SH>(new Nizk_SH
    (hash_, randgen_, CL_, pks, Bs_, *R_, n_, t_, q_, r, Vis_));
}

bool QCLPVSS::verifySharing(vector<unique_ptr<const PublicKey>>& pks, unique_ptr<Nizk_SH> pf) const 
{
  return pf->verify(pks, Bs_, *R_, Vis_);
}

unique_ptr<const Share> QCLPVSS::decShare(const SecretKey& sk, size_t i) const 
{
  CL_.Cl_Delta().nupow(*fi_, *R_, sk);
  CL_.Cl_Delta().nucompinv(*fi_, *Bs_[i], *fi_);

  //return Ai on the form of a share <i, Ai>
  return unique_ptr<const Share>(new Share(i + 1, Mpz(CL_.dlog_in_F(*fi_)))); 
}

unique_ptr<Nizk_DLEQ> QCLPVSS::decShare(const PublicKey& pk, const SecretKey& sk, size_t i) const 
{
  QFI Mi;

  CL_.Cl_Delta().nucompinv(Mi, *Bs_[i], *fi_);

  return unique_ptr<Nizk_DLEQ>(new Nizk_DLEQ(hash_, randgen_, CL_, *R_, pk.get(), Mi, sk));
}

unique_ptr<const Mpz> QCLPVSS::rec(vector<unique_ptr<const Share>>& Ais) const 
{
  // |T| < t + k
  if (Ais.size() < t_ + k_)
    return nullptr;
  
  return sss_.reconstructSecret(Ais);
}

bool QCLPVSS::verifyDec(const Share& Ai, const PublicKey& pki, const Nizk_DLEQ& pf, size_t i) const 
{
  QFI Mi(CL_.power_of_f(Ai.y()));
  CL_.Cl_Delta().nucompinv(Mi, *Bs_[i] , Mi);

  return pf.verify(*R_, pki.get(), Mi);
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