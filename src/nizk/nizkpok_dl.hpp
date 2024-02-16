#ifndef NIZKPOK_DL_HPP__
#define NIZKPOK_DL_HPP__

#include "qclpvss_utils.hpp"
#include "bicycl.hpp"

namespace NIZKPOK_DL_
{
    using namespace UTILS;
    using namespace BICYCL;
    using namespace OpenSSL;

    class NizkPoK_DL {

        protected:
        Mpz A_;
        HashAlgo & h_;
        std::vector<Mpz> b_, u_;

        public:

        NizkPoK_DL(HashAlgo &hash, RandGen &randgen, const CL_HSMqk &cl_hsm,
            const SecLevel & seclevel, const PublicKey &x, const SecretKey &w, const size_t l);

        bool Verify(const CL_HSMqk &cl_hsm, const PublicKey &x, const size_t l) const;
    };

}

#endif