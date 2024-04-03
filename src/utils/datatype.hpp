#ifndef DATATYPE_HPP__
#define DATATYPE_HPP__

#include <bicycl.hpp>
#include <memory>
#include <nizk_sh.hpp>
#include <nizk_sh_ext.hpp>
#include <nizkpok_dl.hpp>
#include <sss.hpp>

using namespace BICYCL;
using namespace std;
using namespace NIZK;
using namespace SSS_;
using namespace UTILS;

namespace DATATYPE {
    class EncShares {
      public:
        Mpz r;
        QFI R;
        unique_ptr<vector<shared_ptr<QFI>>> Bs;
        unique_ptr<Nizk_SH> pf;

        EncShares(size_t n);
    };

    class EncSharesExt {
      public:
        Mpz r_;
        QFI R_;
        unique_ptr<vector<shared_ptr<QFI>>> Bs_;
        unique_ptr<vector<shared_ptr<ECPoint>>> Ds_;
        unique_ptr<Nizk_SH_ext> pf_;

        EncSharesExt(size_t n);
        EncSharesExt(size_t, EncShares& enc_sh);
    };

    class DecShare {
      public:
        unique_ptr<const Share> sh;
        unique_ptr<Nizk_DLEQ> pf;

        DecShare();
    };

    class KeyPair {
      public:
        unique_ptr<const PublicKey> pk_;
        unique_ptr<const SecretKey> sk_;
        unique_ptr<NizkPoK_DL> pf_;

        KeyPair();
    };

}    // namespace DATATYPE

#endif