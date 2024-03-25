#ifndef QCLPVSS_EXT_HPP__
#define QCLPVSS_EXT_HPP__

#include <qclpvss.hpp>
#include <nizk_sh_ext.hpp>

using namespace NIZK;

namespace QCLPVSS_
{
    class QCLPVSS_ext : public QCLPVSS
    {
        protected:

        const ECGroup& ec_group_;

        public:
            QCLPVSS_ext(SecLevel&, HashAlgo &, RandGen&, const ECGroup&, Mpz &q, const size_t k,
                const size_t n, const size_t t);

            unique_ptr<EncSharesExt> share(vector<unique_ptr<const PublicKey>>&) const;

    };
}

#endif
