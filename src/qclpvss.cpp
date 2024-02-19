#include "qclpvss.hpp"
#include "utils/sss.hpp"

using namespace QCLPVSS_;
using namespace NIZKPOK_DL_;
using namespace SSS_;
using namespace UTILS;
using namespace BICYCL;
using namespace OpenSSL;

QCLPVSS::QCLPVSS (SecLevel seclevel, HashAlgo &hash, RandGen &alphas, RandGen &betas, 
    Mpz &q, const size_t k, const size_t n, const size_t t, bool compact_variant) :
      cl_hsmqk_(CL_HSMqk (q, k, seclevel, alphas, compact_variant)),
      seclevel_(seclevel),
      alphas_(alphas),
      betas_(betas),
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

void QCLPVSS::dist(RandGen &randgen, const PublicKey &pk, const Mpz &s) const 
{
  std::vector<Mpz> shares(n_);
  SSS shamir(randgen, t_, n_, q_);
  shamir.shareSecret(s, shares); //figure out how
}


const SecLevel & QCLPVSS::lambda() const {
  return seclevel_;
}