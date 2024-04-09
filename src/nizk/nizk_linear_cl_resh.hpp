#ifndef NIZK_LINEAR_CL_RESH_HPP__
#define NIZK_LINEAR_CL_RESH_HPP__

#include "nizk_linear_cl_base.hpp"
#include <bicycl.hpp>

using namespace BICYCL;
using namespace OpenSSL;

namespace NIZK {
    class NizkLinCLResh
        : public virtual BaseLinCL<
              const tuple<const Mpz&, const SecretKey&>&,    // r, sk\bar
              const QFI&,                                    // U
              const QFI&,                                    // R_0\bar
              const QFI&,                                    // B_0\bar
              const QFI&,                                    // V
              const QFI&,                                    // g_q / h
              const PublicKey&,                              // pk\bar
              const QFI&>                                    // R
    {

        // Alias: Witness = (r, sk\bar)
        using Witness = tuple<const Mpz&, const SecretKey&>;

      public:
        NizkLinCLResh(HashAlgo&, RandGen&, const CL_HSMqk&, const SecLevel&);

        virtual void prove(const Witness& w, const QFI& U, const QFI& R0_,
            const QFI& B0_, const QFI& V, const QFI& h, const PublicKey& pk_,
            const QFI& R) override;

        virtual bool verify(const QFI& U, const QFI& R0_, const QFI& B0_,
            const QFI& V, const QFI& h, const PublicKey& pk_,
            const QFI& R) const override;
    };
}    // namespace NIZK

#endif