#ifndef NIZKPOK_DL_HPP__
#define NIZKPOK_DL_HPP__

#include "bicycl.hpp"
#include "nizk_base.hpp"
#include "qclpvss_utils.hpp"

using namespace UTILS;
using namespace BICYCL;
using namespace OpenSSL;
using namespace std;

namespace NIZK {
    class NizkDL : public virtual BaseNizk<const SecretKey, const PublicKey> {

      protected:
        unsigned int l_;
        Mpz A_, S_, ell_;
        vector<Mpz> b_, u_;

      public:
        NizkDL(HashAlgo&, RandGen&, const CL_HSMqk&, const SecLevel&);

        virtual void prove(const SecretKey&, const PublicKey&) override;
        virtual bool verify(const PublicKey& pk) const override;
    };

}    // namespace NIZK

#endif