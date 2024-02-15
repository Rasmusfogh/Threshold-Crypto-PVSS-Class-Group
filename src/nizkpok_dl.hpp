#ifndef NIZKPOK_DL_HPP__
#define NIZKPOK_DL_HPP__

#include "qclpvss_utils.hpp"

namespace NIZKPOK_DL_
{
    using namespace UTILS;
    using namespace BICYCL;
    using namespace OpenSSL;

    class NizkPoK_DL {

        protected:
        HashAlgo & h_;
        Mpz u_, c_;

        public:

        NizkPoK_DL(HashAlgo &hash, RandGen &randgen, const CL_HSMqk &cl_hsm,
            const PublicKey &x, const SecretKey &w);

        bool Verify(const CL_HSMqk &cl_hsm, const PublicKey &x) const;
    };

}

#endif