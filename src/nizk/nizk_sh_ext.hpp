#ifndef NIZK_SH_EXT_HPP__
#define NIZK_SH_EXT_HPP__

#include "nizk_dleq_mix.hpp"
#include "nizk_sh_base.hpp"
#include "sss.hpp"
#include <bicycl.hpp>
#include <memory>

using namespace BICYCL;
using namespace OpenSSL;
using namespace std;
using namespace SSS_;
using namespace UTILS;

namespace NIZK {
    // Forward declaration
    class NizkDLEQ;

    class NizkExtSH : public virtual BaseNizkSH<
                          const tuple<vector<unique_ptr<const Share>>&,
                              const Mpz&>&,    // p(X), r
                          const vector<unique_ptr<const PublicKey>>&,    // pks
                          const vector<shared_ptr<QFI>>&,                // Bs
                          const vector<shared_ptr<ECPoint>>&,            // Ds
                          const QFI&>                                    // R
    {

        // Alias: Witness = (p(X), r)
        using Witness = tuple<vector<unique_ptr<const Share>>&, const Mpz&>;

      protected:
        unique_ptr<NizkMixDLEQ> pf_;

      private:
        const ECGroup& ec_group_;

      public:
        NizkExtSH(HashAlgo&, RandGen&, const CL_HSMqk&, const SecLevel&,
            const ECGroup&, const size_t n, const size_t t, const Mpz& q,
            const vector<Mpz>& Vis);

        virtual void prove(const Witness& w,
            const vector<unique_ptr<const PublicKey>>&,
            const vector<shared_ptr<QFI>>& Bs,
            const vector<shared_ptr<ECPoint>>& Ds, const QFI& R) override;

        virtual bool verify(const vector<unique_ptr<const PublicKey>>&,
            const vector<shared_ptr<QFI>>& Bs,
            const vector<shared_ptr<ECPoint>>& Ds, const QFI& R) const override;
    };
}    // namespace NIZK

#endif