#ifndef NIZK_LINEAR_CL_BASE_HPP__
#define NIZK_LINEAR_CL_BASE_HPP__

#include "nizk_base.hpp"
#include <bicycl.hpp>

using namespace OpenSSL;
using namespace BICYCL;

namespace NIZK {
    template <typename Witness, typename... Statement>
    class BaseLinCL : public BaseNizk<Witness, Statement...> {

      protected:
        Mpz A_, C_, S_, SCA_;
        Mpz c_;
        vector<Mpz> u_;

      public:
        BaseLinCL(HashAlgo& hash, RandGen& rand, const CL_HSMqk& cl,
            const SecLevel& seclevel, size_t m)
            : BaseNizk<Witness, Statement...>(hash, rand, cl), u_(m) {

            // 2^seclevel
            Mpz::mulby2k(C_, 1, seclevel.soundness() - 1);

            // Compute boundary A and S
            Mpz::mul(S_, cl.Cl_DeltaK().class_number_bound(), C_);
            Mpz::mul(A_, S_, C_);

            Mpz::mul(SCA_, S_, C_);
            Mpz::add(SCA_, SCA_, A_);
        }
    };
}    // namespace NIZK

#endif
