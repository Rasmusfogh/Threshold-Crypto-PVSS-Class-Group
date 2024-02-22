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
      n_(n),
      t_(t),
      q_(q)    
{
  /* Checks */
  if (Mpz(n + k) > q)
      throw std::invalid_argument ("n + k must be less than or equal to q");
  if (t_ + k > n_)
      throw std::invalid_argument ("k + t must be less than or equal to n");    
}

SecretKey QCLPVSS::keyGen(RandGen &randgen) const
{
    return SecretKey(this->cl_hsmqk_, randgen);
}

PublicKey QCLPVSS::keyGen(const SecretKey &sk) const
{
    return PublicKey(this->cl_hsmqk_, sk);
}

NizkPoK_DL QCLPVSS::keyGen(RandGen &randgen, const PublicKey &pk, const SecretKey & sk) const
{
  return NizkPoK_DL(hash_, randgen, this->cl_hsmqk_, lambda(), pk, sk);
}

bool QCLPVSS::verifyKey(SecretKey &sk, PublicKey &pk, NizkPoK_DL &pf) const 
{
  return pf.Verify(this->cl_hsmqk_, pk);
}

const vector<Share>& QCLPVSS::dist(RandGen &randgen, const Mpz &s) const 
{
  vector<Share> shares(n_);
  SSS shamir(randgen, t_, n_, q_);
  shamir.shareSecret(s, shares);

  return shares;
}

void QCLPVSS::dist(RandGen &randgen, const PublicKey &pk, const Share& share) const 
{
  QFI R, f, pkr, B;

  Mpz r(randgen.random_mpz(cl_hsmqk_.secretkey_bound()));
  cl_hsmqk_.power_of_h(R, r);
  f = cl_hsmqk_.power_of_f(share.y());
  pk.exponentiation(cl_hsmqk_, pkr, r);

  //Could just put it into pkr or f instead of B. Just for the understanding of things
  cl_hsmqk_.Cl_Delta().nucomp(B, pkr, f);

  //Probably needs another hash function
  Nizk_SH pf(hash_, randgen, this->cl_hsmqk_, seclevel_, pk, B, R, n_, t_, q_, share.x());
}


const SecLevel & QCLPVSS::lambda() const {
  return seclevel_;
}