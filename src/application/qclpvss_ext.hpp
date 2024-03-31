#ifndef QCLPVSS_EXT_HPP__
#define QCLPVSS_EXT_HPP__

#include <nizk_sh_ext.hpp>
#include <qclpvss.hpp>

using namespace NIZK;

namespace QCLPVSS_ {
    class QCLPVSS_ext : public QCLPVSS {
      protected:
        const ECGroup& ec_group_;

      public:
        QCLPVSS_ext(SecLevel&, HashAlgo&, RandGen&, const ECGroup&, Mpz& q,
            const size_t k, const size_t n, const size_t t);

        unique_ptr<EncSharesExt> share(
            vector<unique_ptr<const PublicKey>>&) const;

        unique_ptr<ECPoint> generate_sk_share(
            const vector<unique_ptr<ECPoint>>& Ds) const;

        unique_ptr<Mpz> compute_sk(const vector<unique_ptr<QFI>>& Bs,
            const vector<QFI>& Rs, const SecretKey& ski) const;
    };
}    // namespace QCLPVSS_

#endif
