#ifndef NIZK_DLEQ_RESH_HPP__
#define NIZK_DLEQ_RESH_HPP__

#include "nizk_dleq_base.hpp"
#include <bicycl.hpp>

using namespace BICYCL;
using namespace OpenSSL;

namespace NIZK {
    class NizkDLEQResh
        : public virtual BaseNizkDLEQ<
              const tuple<const Mpz&, const SecretKey&>,    // Witnesses r,
                                                            // sk\bar
              const QFI&,                                   // U
              const QFI&,                                   // R_0\bar
              const QFI&,                                   // B_0\bar
              const QFI&,                                   // V
              const QFI&,                                   // g_q / h
              const PublicKey&,                             // pk\bar
              const QFI&>                                   // R
    {
      protected:
        Mpz A_, C_, S_;
        Mpz u_, c_;

      public:
        NizkDLEQResh(HashAlgo&, RandGen&, const CL_HSMqk&, const SecLevel&);

        virtual void prove(const tuple<const Mpz&, const SecretKey&>& W,
            const QFI& U, const QFI& R0_, const QFI& B0_, const QFI& V,
            const QFI& h, const PublicKey& pk_, const QFI& R) override;

        virtual bool verify(const QFI& U, const QFI& R0_, const QFI& B0_,
            const QFI& V, const QFI& h, const PublicKey& pk_,
            const QFI& R) const override;
    };
}    // namespace NIZK

#endif