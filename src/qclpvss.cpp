#include "qclpvss.hpp"

using namespace QCLPVSS_;
using namespace NIZK;
using namespace SSS_;
using namespace UTILS;
using namespace BICYCL;
using namespace OpenSSL;

QCLPVSS::QCLPVSS (SecLevel seclevel, HashAlgo &hash, RandGen& randgen, Mpz &q, const size_t k, 
  const size_t n, const size_t t, bool compact_variant) :
      cl_hsmqk_(CL_HSMqk (q, k, seclevel, randgen, compact_variant)),
      seclevel_(seclevel),
      randgen_(randgen),
      hash_(hash),
      k_(k),
      n_(n),
      t_(t),
      q_(q),
      R_(unique_ptr<QFI>(new QFI))
{
  /* Checks */
  if (Mpz(n + k) > q)
      throw std::invalid_argument ("n + k must be less than or equal to q");
  if (t_ + k > n_)
      throw std::invalid_argument ("k + t must be less than or equal to n");    

    Bs_.reserve(n_);
    generate_n(back_inserter(Bs_), n_, [] {return unique_ptr<QFI>(new QFI); });
}

unique_ptr<const SecretKey> QCLPVSS::keyGen(RandGen &randgen) const
{
    return unique_ptr<const SecretKey>(new SecretKey(this->cl_hsmqk_, randgen));
}

unique_ptr<const PublicKey> QCLPVSS::keyGen(const SecretKey& sk) const
{
    return unique_ptr<const PublicKey>(new PublicKey(this->cl_hsmqk_, sk));
}

unique_ptr<NizkPoK_DL> QCLPVSS::keyGen(const PublicKey& pk, const SecretKey& sk) const
{
  return unique_ptr<NizkPoK_DL>(new NizkPoK_DL(hash_, randgen_, this->cl_hsmqk_, seclevel_, pk, sk));
}

bool QCLPVSS::verifyKey(const PublicKey& pk,  unique_ptr<NizkPoK_DL>pf) const 
{
  return pf->verify(this->cl_hsmqk_, pk);
}

unique_ptr<vector<unique_ptr<const Share>>> QCLPVSS::dist(const Mpz &s) const 
{
  SSS shamir(randgen_, t_, n_, q_);
  return shamir.shareSecret(s);
}

unique_ptr<Nizk_SH> QCLPVSS::dist(vector<unique_ptr<const PublicKey>>& pks, 
                   vector<unique_ptr<const Share>>& shares) const 
{
  QFI f, pkr;

  const Mpz r(randgen_.random_mpz(cl_hsmqk_.secretkey_bound()));
  cl_hsmqk_.power_of_h(*R_, r);

  for(size_t i = 0; i < n_; i++)
  {
    f = cl_hsmqk_.power_of_f(shares[i]->y());
    pks[i]->exponentiation(cl_hsmqk_, pkr, r);
    //Could just put it into pkr or f instead of B. Just for the understanding of things
    cl_hsmqk_.Cl_Delta().nucomp(*Bs_[i], pkr, f);
  }

  return unique_ptr<Nizk_SH>(new Nizk_SH
    (hash_, randgen_, this->cl_hsmqk_, seclevel_, pks, Bs_, *R_, n_, t_, q_, r));
}

bool QCLPVSS::verifySharing(vector<unique_ptr<const PublicKey>>& pks, unique_ptr<Nizk_SH> pf) const 
{
  return pf->verify(this->cl_hsmqk_, pks, Bs_, *R_);
}

unique_ptr<const Share> QCLPVSS::decShare(const SecretKey& sk, size_t i) const 
{
  cl_hsmqk_.Cl_G().nupow(*fi_, *R_, sk);
  cl_hsmqk_.Cl_Delta().nucompinv(*fi_, *Bs_[i], *fi_);

  //return Ai on the form of a share <i, Ai>
  return unique_ptr<const Share>(new Share(i, Mpz(cl_hsmqk_.dlog_in_F(*fi_)))); 
}

unique_ptr<Nizk_DLEQ> QCLPVSS::decShare(const PublicKey& pk, const SecretKey& sk, size_t i) const 
{
  QFI Mi;

  cl_hsmqk_.Cl_Delta().nucompinv(Mi, *Bs_[i], *fi_);

  return unique_ptr<Nizk_DLEQ>(new Nizk_DLEQ
    (hash_, randgen_, this->cl_hsmqk_, seclevel_, *R_, pk, Mi, sk));
}

const Mpz& QCLPVSS::rec(vector<unique_ptr<const Share>>& Ais) const 
{
  // |T| < t + k
  if (Ais.size() < t_ + k_)
    return Mpz();
  
  Mpz s, product;
  //T' \subset T, |T'| = t + k
  size_t T_p = t_ + k_;
  for(size_t i = 0; i < T_p; i++)
  {

    Mpz::add(s, s, product);
  }
}