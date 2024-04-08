#ifndef NIZK_SH_HPP__
#define NIZK_SH_HPP__

#include "nizk_sh_base.hpp"
#include "sss.hpp"

using namespace std;
using namespace SSS_;

namespace NIZK {
    class NizkResh
        : public virtual BaseNizkSH<
              tuple<Mpz, Mpz, vector<unique_ptr<const Share>>&>,    // w = (sk',
                                                                    // r, p(X))
              const vector<unique_ptr<const PublicKey>>,            // pks
              const PublicKey,                                      // pk'
              const QFI,                                            // R'
              const QFI,                                            // B'
              const QFI,                                            // R
              const vector<shared_ptr<QFI>>>                        // Bs

    {
        NizkResh(HashAlgo&, RandGen&, const CL_HSMqk&, const SecLevel&,
            const size_t n, const size_t t, const Mpz& q,
            const vector<Mpz>& Vis);

        virtual void prove(
            const tuple<Mpz, Mpz, vector<unique_ptr<const Share>>&>& w,
            const vector<unique_ptr<const PublicKey>>&, const PublicKey&,
            const QFI&, const QFI&, const QFI&,
            const vector<shared_ptr<QFI>>&) override;

        virtual bool verify(const vector<unique_ptr<const PublicKey>>&,
            const PublicKey&, const QFI&, const QFI&, const QFI&,
            const vector<shared_ptr<QFI>>&) const override;
    };
}    // namespace NIZK

#endif