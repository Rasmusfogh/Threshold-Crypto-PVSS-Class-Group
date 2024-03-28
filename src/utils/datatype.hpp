#ifndef DATATYPE_HPP__
#define DATATYPE_HPP__

#include <bicycl.hpp>
#include <memory>
#include <nizk_sh.hpp>
#include <nizk_sh_ext.hpp>
#include <sss.hpp>

using namespace BICYCL;
using namespace std;
using namespace NIZK;
using namespace SSS_;

namespace DATATYPE
{
    class EncShares
    {
        public:
            Mpz r;
            QFI R;
            unique_ptr<vector<unique_ptr<QFI>>> Bs;
            unique_ptr<Nizk_SH> pf;

            EncShares(size_t n);
    };

    class EncSharesExt
    {
         public:
            Mpz r_;
            QFI R_;
            unique_ptr<vector<unique_ptr<QFI>>> Bs_;
            unique_ptr<vector<unique_ptr<ECPoint>>> Ds_;
            unique_ptr<Nizk_SH_ext> pf_;

            EncSharesExt(size_t n, const ECGroup& ec_group_);
    };

    class DecShare
    {
        public:
            unique_ptr<const Share> sh;
            unique_ptr<Nizk_DLEQ> pf;

            DecShare();
    };
}

#endif