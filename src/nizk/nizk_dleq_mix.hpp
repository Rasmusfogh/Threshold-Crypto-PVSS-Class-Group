#ifndef NIZK_DLEQ_MIX_HPP__
#define NIZK_DLEQ_MIX_HPP__

#include "nizk_linear_cl_base.hpp"
#include "sss.hpp"
#include <bicycl.hpp>

using namespace BICYCL;
using namespace OpenSSL;
using namespace std;
using namespace SSS_;

namespace NIZK {
    class NizkMixDLEQ : public virtual BaseNizkLinCL<
                            const tuple<const Mpz&, const Mpz&>&,    // r, d
                            const QFI&,                              // U
                            const QFI&,                              // M
                            const QFI&,                              // R
                            const QFI&,                              // V
                            const QFI&,                              // B
                            const ECPoint&>                          // D

    {

        // Alias: Witness = (r, d)
        using Witness = tuple<const Mpz&, const Mpz&>;

      private:
        const ECGroup& ec_group_;

      public:
        NizkMixDLEQ(HashAlgo&, RandGen&, const CL_HSMqk&, const SecLevel&,
            const ECGroup&);

        void prove(const Witness& w, const QFI& X1, const QFI& X2,
            const QFI& Y1, const QFI& Y2, const QFI& Y3,
            const ECPoint& Y4) override;

        bool verify(const QFI& X1, const QFI& X2, const QFI& Y1, const QFI& Y2,
            const QFI& Y3, const ECPoint& Y4) const override;
    };
}    // namespace NIZK
#endif