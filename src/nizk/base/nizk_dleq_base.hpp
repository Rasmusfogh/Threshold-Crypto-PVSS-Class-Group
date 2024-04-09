#ifndef NIZK_DLEQ_BASE_HPP__
#define NIZK_DLEQ_BASE_HPP__

#include "nizk_base.hpp"
#include <bicycl.hpp>

using namespace OpenSSL;
using namespace BICYCL;

namespace NIZK {
    template <typename Witness, typename... Statement>
    class BaseNizkDLEQ : public BaseNizk<Witness, Statement...> {

      protected:
        Mpz A_, C_, S_;
        Mpz u_, c_;

      public:
        BaseNizkDLEQ(HashAlgo& hash, RandGen& rand, const CL_HSMqk& cl,
            const SecLevel& seclevel)
            : BaseNizk<Witness, Statement...>(hash, rand, cl) {

            // 2^seclevel
            Mpz::mulby2k(C_, 1, seclevel.soundness() - 1);

            // Compute boundary A and S
            Mpz::mul(S_, cl.Cl_DeltaK().class_number_bound(), C_);
            Mpz::mul(A_, S_, C_);
        }
    };
}    // namespace NIZK

#endif
