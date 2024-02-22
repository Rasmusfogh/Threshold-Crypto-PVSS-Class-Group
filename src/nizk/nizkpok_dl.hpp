#ifndef NIZKPOK_DL_HPP__
#define NIZKPOK_DL_HPP__

#include "qclpvss_utils.hpp"
#include "bicycl.hpp"

using namespace UTILS;
using namespace BICYCL;
using namespace OpenSSL;

namespace NIZKPOK_DL_
{
    class NizkPoK_DL {

        protected:
        Mpz A_;
        HashAlgo & h_;
        static const size_t rounds_ = 40;
        std::array<Mpz, rounds_> b_, u_;

        public:

        NizkPoK_DL(HashAlgo &hash, RandGen &randgen, const CL_HSMqk &cl_hsm,
            const SecLevel & seclevel, const PublicKey &x, const SecretKey &w);

        bool Verify(const CL_HSMqk &cl_hsm, const PublicKey &x) const;
    };

}

#endif