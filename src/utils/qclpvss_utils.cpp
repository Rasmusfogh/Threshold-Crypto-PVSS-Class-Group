#include "qclpvss_utils.hpp"

using namespace UTILS;
using namespace BICYCL;

SecretKey::SecretKey(const CL_HSMqk &cl_hsm, RandGen &r) 
  : Mpz(r.random_mpz(cl_hsm.secretkey_bound()))
{ }


PublicKey::PublicKey(const CL_HSMqk &cl_hsm, const SecretKey &sk)
{
  cl_hsm.power_of_h(pk_, sk);

  //not sure what below is yet
  d_ = (cl_hsm.encrypt_randomness_bound().nbits() + 1)/2;
  e_ = d_/2 + 1;

  pk_de_precomp_ = pk_;
  for (size_t i = 0; i < d_+e_; i++)
  {
      if (i == e_)
      pk_e_precomp_ = pk_de_precomp_;
      if (i == d_)
      pk_d_precomp_ = pk_de_precomp_;
      cl_hsm.Cl_G().nudupl (pk_de_precomp_, pk_de_precomp_);
  }
}

const QFI & PublicKey::get () const
{
  return pk_;
}

void PublicKey::exponentiation (const CL_HSMqk &cl_hsm, QFI &r, const Mpz &n) const
{
  cl_hsm.Cl_G().nupow (r, pk_, n, d_, e_, pk_e_precomp_, pk_d_precomp_, pk_de_precomp_);
}

