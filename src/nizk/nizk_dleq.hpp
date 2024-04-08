#ifndef NIZK_DLEQ_HPP__
#define NIZK_DLEQ_HPP__

#include "nizk_base.hpp"
#include <bicycl.hpp>

using namespace BICYCL;
using namespace OpenSSL;
using namespace std;

namespace NIZK {
    class NizkDLEQ : public virtual BaseNizk<const Mpz,    // r
                         const QFI,                        // g_q / h
                         const QFI,                        // U
                         const QFI,                        // R
                         const QFI>                        // V
    {
      protected:
        Mpz A_, C_, S_;
        Mpz u_, c_;

      public:
        NizkDLEQ(HashAlgo&, RandGen&, const CL_HSMqk&, const SecLevel&);

        void prove(const Mpz& w, const QFI& X1, const QFI& X2, const QFI& Y1,
            const QFI& Y2) override;
        bool verify(const QFI& X1, const QFI& X2, const QFI& Y1,
            const QFI& Y2) const override;
    };
}    // namespace NIZK
#endif