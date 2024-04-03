#ifndef NIZK_SH_EXT_HPP__
#define NIZK_SH_EXT_HPP__

#include "bicycl.hpp"
#include "nizk/nizk_dleq_mix.hpp"
#include "qclpvss_utils.hpp"
#include <memory>
#include <nizk_sh_base.hpp>
#include <sss.hpp>

using namespace UTILS;
using namespace BICYCL;
using namespace OpenSSL;
using namespace std;
using namespace SSS_;

namespace NIZK {
    // Forward declaration
    class Nizk_DLEQ;

    class Nizk_SH_ext
        : public virtual Nizk_SH_base<
              pair<vector<unique_ptr<const Share>>&, Mpz>,    // p(X), r
              const vector<unique_ptr<const PublicKey>>,      // pks
              const vector<shared_ptr<QFI>>,                  // Bs
              const vector<shared_ptr<ECPoint>>,              // Ds
              const QFI>                                      // R
    {

      protected:
        unique_ptr<Nizk_DLEQ_mix> pf_;

      private:
        const ECGroup& ec_group_;

      public:
        Nizk_SH_ext(HashAlgo&, RandGen&, const CL_HSMqk&, const SecLevel&,
            const ECGroup&, const size_t n, const size_t t, const Mpz& q,
            const vector<Mpz>& Vis);

        virtual void prove(
            const pair<vector<unique_ptr<const Share>>&, Mpz>& rd,
            const vector<unique_ptr<const PublicKey>>&,
            const vector<shared_ptr<QFI>>& Bs,
            const vector<shared_ptr<ECPoint>>& Ds, const QFI& R) override;

        virtual bool verify(const vector<unique_ptr<const PublicKey>>&,
            const vector<shared_ptr<QFI>>& Bs,
            const vector<shared_ptr<ECPoint>>& Ds, const QFI& R) const override;
    };
}    // namespace NIZK

#endif