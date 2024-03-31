#include "qclpvss_utils.hpp"

using namespace UTILS;
using namespace BICYCL;

SecretKey::SecretKey(const CL_HSMqk& cl, RandGen& r)
    : Mpz(r.random_mpz(cl.secretkey_bound())) {}

PublicKey::PublicKey(const CL_HSMqk& cl, const SecretKey& sk) {
    cl.power_of_h(pk_, sk);

    d_ = (cl.encrypt_randomness_bound().nbits() + 1) / 2;
    e_ = d_ / 2 + 1;

    pk_de_precomp_ = pk_;
    for (size_t i = 0; i < d_ + e_; i++) {
        if (i == e_)
            pk_e_precomp_ = pk_de_precomp_;
        if (i == d_)
            pk_d_precomp_ = pk_de_precomp_;
        cl.Cl_G().nudupl(pk_de_precomp_, pk_de_precomp_);
    }
}

const QFI& PublicKey::get() const {
    return pk_;
}

void PublicKey::exponentiation(const CL_HSMqk& cl, QFI& r, const Mpz& n) const {
    cl.Cl_G().nupow(r, pk_, n, d_, e_, pk_e_precomp_, pk_d_precomp_,
        pk_de_precomp_);
}
