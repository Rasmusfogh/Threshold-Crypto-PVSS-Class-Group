#include "nizk_dl.hpp"
#include <thread>

using namespace BICYCL;
using namespace OpenSSL;
using namespace NIZK;
using namespace UTILS;

NizkDL::NizkDL(HashAlgo& hash, RandGen& rand, const CL_HSMqk& cl,
    const SecLevel& seclevel)
    : ell_(static_cast<unsigned long>(cl_.lambda_distance() - 2)),
      BaseNizk(hash, rand, cl), l_(cl_.lambda_distance() - 2), u_(l_) {

    b_.reserve(l_);

    // 2^seclevel
    Mpz bits;
    Mpz::mulby2k(bits, 1, seclevel.soundness() - 1);

    // Compute boundary A and S
    Mpz::mul(S_, cl.Cl_DeltaK().class_number_bound(), bits);
    Mpz::mul(A_, S_, bits);
}

void NizkDL::prove(const SecretKey& sk, const PublicKey& pk) {
    Mpz temp;
    vector<Mpz> r;
    r.reserve(l_);
    vector<QFI> t(l_);

    for (size_t i = 0; i < l_; i++)
        r.emplace_back(rand_.random_mpz(A_));

    vector<future<void>> futures;

    for (size_t i = 0; i < l_; i++)
        futures.emplace_back(
            pool->enqueue([&, i]() { cl_.power_of_h(t[i], r[i]); }));

    for (auto& ft : futures)
        ft.get();

    init_random_oracle(cl_.h(), pk.get(), t);

    for (size_t i = 0; i < l_; i++) {
        b_.emplace_back(query_random_oracle(ell_));
        Mpz::mul(temp, sk, b_[i]);
        Mpz::add(u_[i], temp, r[i]);
    }
}

bool NizkDL::verify(const PublicKey& x) const {
    vector<QFI> t(l_);

    Mpz AS_;
    Mpz::add(AS_, A_, S_);

    for (size_t i = 0; i < l_; i++)
        if (u_[i] > AS_)
            return false;

    vector<future<void>> futures;

    for (size_t i = 0; i < l_; i++)
        futures.emplace_back(pool->enqueue([&, i]() {
            QFI temp;
            x.exponentiation(cl_, t[i], b_[i]);
            cl_.power_of_h(temp, u_[i]);
            cl_.Cl_Delta().nucompinv(t[i], temp, t[i]);
        }));

    for (auto& ft : futures)
        ft.get();

    init_random_oracle(cl_.h(), x.get(), t);

    for (const auto& _ : b_)
        if (_ != query_random_oracle(ell_))
            return false;

    return true;
}