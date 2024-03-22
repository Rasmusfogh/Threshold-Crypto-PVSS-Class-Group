#ifndef NIZK_DLEQ_MIX_HPP__
#define NIZK_DLEQ_MIX_HPP__

#include <secp256k1_wrapper.hpp>
#include "qclpvss_utils.hpp"
#include "bicycl.hpp"
#include "nizk_base.hpp"
#include "sss.hpp"
using namespace UTILS;
using namespace BICYCL;
using namespace OpenSSL;
using namespace std;
using namespace SSS_;
using namespace EC;

namespace NIZK
{
    class Nizk_DLEQ_mix : public virtual Nizk_base<const pair<Mpz, Mpz>,      // r, d
                                                    const QFI,                // U                                            
                                                    const QFI,                // M                                        
                                                    const QFI,                // R
                                                    const QFI,                // V
                                                    const QFI,                // B
                                                    const Mpz>                // D

    {
        protected:
            Mpz A_, C_;
            Mpz c_, ud_, ur_;

        private:
            Secp256k1& secp256k1_;

        public:
            Nizk_DLEQ_mix(HashAlgo&, RandGen&, const CL_HSMqk&, Secp256k1&);

            void prove(const pair<Mpz, Mpz>& w, const QFI& X1, const QFI& X2, 
                const QFI& Y1, const QFI& Y2, const QFI& Y3, const Mpz& Y4) override;

            bool verify(const QFI& X1, const QFI& X2, const QFI& Y1, const QFI& Y2,
                const QFI& Y3, const Mpz& Y4) const override;
    };
}
#endif