#ifndef NIZK_RESH_HPP__
#define NIZK_RESH_HPP__

#include "nizk_dleq_resh.hpp"
#include "nizk_sh_base.hpp"
#include "sss.hpp"

using namespace SSS_;

namespace NIZK {
    class NizkDLEQ;

    class NizkResh : public virtual BaseNizkSH<
                         const tuple<const SecretKey&, const Mpz&,
                             vector<unique_ptr<const Share>>&>&,    // w = (sk',
                                                                    // r, p(X))
                         const vector<unique_ptr<const PublicKey>>&,    // pks
                         const PublicKey&,                              // pk'
                         const QFI&,                                    // R'
                         const QFI&,                                    // B'
                         const QFI&,                                    // R
                         const vector<shared_ptr<QFI>>&>                // Bs

    {
      protected:
        unique_ptr<NizkDLEQResh> pf_;

      public:
        NizkResh(HashAlgo&, RandGen&, const CL_HSMqk&, const SecLevel&,
            const size_t n, const size_t t, const Mpz& q,
            const vector<Mpz>& Vis);

        virtual void prove(const tuple<const SecretKey&, const Mpz&,
                               vector<unique_ptr<const Share>>&>& w,
            const vector<unique_ptr<const PublicKey>>&, const PublicKey&,
            const QFI&, const QFI&, const QFI&,
            const vector<shared_ptr<QFI>>&) override;

        virtual bool verify(const vector<unique_ptr<const PublicKey>>&,
            const PublicKey&, const QFI&, const QFI&, const QFI&,
            const vector<shared_ptr<QFI>>&) const override;
    };
}    // namespace NIZK

#endif