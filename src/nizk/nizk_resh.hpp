#ifndef NIZK_RESH_HPP__
#define NIZK_RESH_HPP__

#include "nizk_linear_cl_resh.hpp"
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

        // Alias: Witness = (sk', r, p(X))
        using Witness = tuple<const SecretKey&, const Mpz&,
            vector<unique_ptr<const Share>>&>;

      protected:
        unique_ptr<NizkLinCLResh> pf_;

      public:
        NizkResh(HashAlgo&, RandGen&, const CL_HSMqk&, const SecLevel&,
            const size_t n, const size_t t, const Mpz& q,
            const vector<Mpz>& Vis);

        virtual void prove(const Witness& w,
            const vector<unique_ptr<const PublicKey>>&, const PublicKey&,
            const QFI&, const QFI&, const QFI&,
            const vector<shared_ptr<QFI>>&) override;

        virtual bool verify(const vector<unique_ptr<const PublicKey>>&,
            const PublicKey&, const QFI&, const QFI&, const QFI&,
            const vector<shared_ptr<QFI>>&) const override;

      protected:
        void computeStatement(QFI& U, QFI& V, QFI& R0, QFI& B0,
            const vector<unique_ptr<const PublicKey>>& pks,
            const vector<shared_ptr<QFI>>& Bs, const QFI& R, const QFI& R_,
            const QFI& B_) const;
    };
}    // namespace NIZK

#endif