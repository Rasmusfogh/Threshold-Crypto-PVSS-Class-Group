#ifndef NIZK_SH_HPP__
#define NIZK_SH_HPP__

#include "bicycl.hpp"
#include "nizk/nizk_dleq.hpp"
#include "qclpvss_utils.hpp"
#include <nizk_sh_base.hpp>

using namespace UTILS;
using namespace BICYCL;
using namespace OpenSSL;
using namespace std;

namespace NIZK {
    // Forward declaration
    class NizkDLEQ;

    class NizkSH : public virtual BaseNizkSH<const Mpz,              // r
                       const vector<unique_ptr<const PublicKey>>,    // pks
                       const vector<shared_ptr<QFI>>,                // Bs
                       const QFI>                                    // R
    {

      protected:
        unique_ptr<NizkDLEQ> pf_;

      public:
        NizkSH(HashAlgo&, RandGen&, const CL_HSMqk&, const SecLevel&,
            const size_t n, const size_t t, const Mpz& q,
            const vector<Mpz>& Vis);

        virtual void prove(const Mpz& r,
            const vector<unique_ptr<const PublicKey>>&,
            const vector<shared_ptr<QFI>>& Bs, const QFI& R) override;

        virtual bool verify(const vector<unique_ptr<const PublicKey>>&,
            const vector<shared_ptr<QFI>>& Bs, const QFI& R) const override;
    };
}    // namespace NIZK

#endif