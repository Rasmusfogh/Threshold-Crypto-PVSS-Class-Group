#include "nizkpok_dl.hpp"

using namespace BICYCL;
using namespace OpenSSL;
using namespace UTILS;
using namespace NIZK;

NizkPoK_DL::NizkPoK_DL(HashAlgo& hash, RandGen& rand, const CL_HSMqk& cl,
    const SecLevel& seclevel)
    : l_boundary(static_cast<unsigned long>(cl_.lambda_distance())),
      Nizk_base(hash, rand, cl), l_(cl_.lambda_distance()), u_(l_) {
    b_.reserve(l_);

    // Compute boundary A and AS
    Mpz S_;
    Mpz::mul(A_, cl.encrypt_randomness_bound(),
        rand.random_mpz_2exp(seclevel.soundness()));
    Mpz::mul(S_, A_, rand.random_mpz_2exp(seclevel.soundness()));
    Mpz::add(AS_, cl.encrypt_randomness_bound(), S_);
}

void NizkPoK_DL::prove(const SecretKey& sk, const PublicKey& pk) {
    Mpz temp;
    vector<Mpz> r;
    r.reserve(l_);
    vector<QFI> t(l_);

    for (size_t i = 0; i < l_; i++) {
        r.emplace_back(rand_.random_mpz(A_));
        cl_.power_of_h(t[i], r[i]);
    }

    initRandomOracle(cl_.h(), pk.get(), t);

    for (size_t i = 0; i < l_; i++) {
        b_.emplace_back(queryRandomOracle(l_boundary));
        Mpz::mul(temp, sk, b_[i]);
        Mpz::add(u_[i], temp, r[i]);
    }
}

bool NizkPoK_DL::verify(const PublicKey& x) const {
    vector<QFI> t(l_);

    QFI temp;

    for (size_t i = 0; i < l_; i++) {

        if (u_[i] > AS_)
            return false;

        x.exponentiation(cl_, t[i], b_[i]);
        cl_.power_of_h(temp, u_[i]);
        cl_.Cl_Delta().nucompinv(t[i], temp, t[i]);
    }

    initRandomOracle(cl_.h(), x.get(), t);

    for (size_t i = 0; i < l_; i++)
        if (b_[i] != queryRandomOracle(l_boundary))
            return false;

    return true;
}