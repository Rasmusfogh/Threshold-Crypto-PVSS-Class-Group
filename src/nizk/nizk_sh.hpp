#ifndef NIZK_SH_HPP__
#define NIZK_SH_HPP__

#include "qclpvss_utils.hpp"
#include "bicycl.hpp"
#include "nizk/nizk_dleq.hpp"

using namespace UTILS;
using namespace BICYCL;
using namespace OpenSSL;
using namespace std;

namespace NIZK
{
    class Nizk_SH {

        protected:
        HashAlgo& h_;
        RandGen& rand_;
        unique_ptr<Nizk_DLEQ> pf_;

        public:

        Nizk_SH(HashAlgo&, RandGen&, const CL_HSMqk&, const SecLevel&, vector<unique_ptr<const PublicKey>>&, 
                const vector<unique_ptr<QFI>>& Bs, const QFI& R, const size_t& n, const size_t& t, const Mpz& q, const Mpz& r);

        bool verify(const CL_HSMqk&, vector<unique_ptr<const PublicKey>>&, const vector<unique_ptr<QFI>>& Bs, 
                    const QFI& R) const;

        private:
        void initRNG(RandGen& randgen, vector<unique_ptr<const PublicKey>>& pks, 
        const vector<unique_ptr<QFI>>& Bs, const QFI& R, const QFI&h, const QFI& f) const;
    };
}

#endif