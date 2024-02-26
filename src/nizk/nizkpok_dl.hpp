#ifndef NIZKPOK_DL_HPP__
#define NIZKPOK_DL_HPP__

#include "qclpvss_utils.hpp"
#include "bicycl.hpp"

using namespace UTILS;
using namespace BICYCL;
using namespace OpenSSL;

namespace NIZK
{
    class NizkPoK_DL {

        protected:
        Mpz A_, AS_;
        HashAlgo & h_;
        static const size_t rounds_ = 40;
        std::array<Mpz, rounds_> b_, u_;

        public:

        NizkPoK_DL(HashAlgo&, RandGen&, const CL_HSMqk&,
            const SecLevel&, const PublicKey&, const SecretKey&);

        bool verify(const CL_HSMqk&, const PublicKey&) const;
    };

}

#endif