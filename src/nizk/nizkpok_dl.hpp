#ifndef NIZKPOK_DL_HPP__
#define NIZKPOK_DL_HPP__

#include "qclpvss_utils.hpp"
#include "bicycl.hpp"
#include "nizk_base.hpp"

using namespace UTILS;
using namespace BICYCL;
using namespace OpenSSL;
using namespace std;

namespace NIZK
{
    class NizkPoK_DL : public virtual Nizk_base<const SecretKey,
                                                const PublicKey> {

        protected:
        unsigned int l_;
        Mpz A_, AS_, l_boundary;
        vector<Mpz> b_, u_;

        public:

        NizkPoK_DL(HashAlgo&, RandGen&, const CL_HSMqk&, const SecLevel&);

        virtual void prove(const SecretKey&, const PublicKey&) override;
        virtual bool verify(const PublicKey& pk) const override;
    };

}

#endif