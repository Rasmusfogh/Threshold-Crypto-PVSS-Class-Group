#ifndef QCLPVSS_EXT_HPP__
#define QCLPVSS_EXT_HPP__

#include <qclpvss.hpp>
#include <nizk_sh_ext.hpp>
#include <secp256k1_wrapper.hpp>

using namespace NIZK;
using namespace EC;

namespace QCLPVSS_
{
    class QCLPVSS_ext : public QCLPVSS
    {
        protected:

        Secp256k1& secp256k1;

        public:
            QCLPVSS_ext(SecLevel&, HashAlgo &, RandGen&, Secp256k1&, Mpz &q, const size_t k,
                const size_t n, const size_t t);

            unique_ptr<EncSharesExt> share(vector<unique_ptr<const PublicKey>>&) const;

    };
}

#endif
