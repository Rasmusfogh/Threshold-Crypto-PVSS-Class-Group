#ifndef NIZK_LINEAR_CL_HPP__
#define NIZK_LINEAR_CL_HPP__

#include "nizk_linear_cl_base.hpp"

namespace NIZK {
    class NizkLinCL : public BaseNizkLinCL<const vector<Mpz>&,
                          const vector<vector<QFI>>&, const vector<QFI>&> {

      public:
        NizkLinCL(HashAlgo& hash, RandGen& rand, const CL_HSMqk& cl,
            const SecLevel& seclevel);

        virtual void prove(const vector<Mpz>& w, const vector<vector<QFI>>& X,
            const vector<QFI>& Y) override;

        virtual bool verify(const vector<vector<QFI>>& X,
            const vector<QFI>& Y) const override;
    };
}    // namespace NIZK

#endif