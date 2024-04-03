#ifndef NIZK_DLEQ_MIX_HPP__
#define NIZK_DLEQ_MIX_HPP__

#include "bicycl.hpp"
#include "nizk_base.hpp"
#include "qclpvss_utils.hpp"
#include "sss.hpp"
using namespace UTILS;
using namespace BICYCL;
using namespace OpenSSL;
using namespace std;
using namespace SSS_;

namespace NIZK {
    class Nizk_DLEQ_mix
        : public virtual Nizk_base<const pair<Mpz, Mpz>,    // r, d
              const QFI,                                    // U
              const QFI,                                    // M
              const QFI,                                    // R
              const QFI,                                    // V
              const QFI,                                    // B
              const ECPoint>                                // D

    {
      protected:
        Mpz A_, C_;
        Mpz c_, ud_, ur_;

      private:
        const ECGroup& ec_group_;

      public:
        Nizk_DLEQ_mix(HashAlgo&, RandGen&, const CL_HSMqk&, const SecLevel&,
            const ECGroup&);

        void prove(const pair<Mpz, Mpz>& w, const QFI& X1, const QFI& X2,
            const QFI& Y1, const QFI& Y2, const QFI& Y3,
            const ECPoint& Y4) override;

        bool verify(const QFI& X1, const QFI& X2, const QFI& Y1, const QFI& Y2,
            const QFI& Y3, const ECPoint& Y4) const override;
    };
}    // namespace NIZK
#endif