#include "datatype.hpp"

using namespace DATATYPE;

EncShares::EncShares(size_t n) {
    Bs = unique_ptr<vector<shared_ptr<QFI>>>(new vector<shared_ptr<QFI>>);

    Bs->reserve(n);
    generate_n(back_inserter(*Bs), n,
        [] { return shared_ptr<QFI>(new QFI()); });
}

EncSharesExt::EncSharesExt(size_t n) {
    Ds_ = unique_ptr<vector<shared_ptr<ECPoint>>>(
        new vector<shared_ptr<ECPoint>>);

    Ds_->reserve(n);
}

EncSharesExt::EncSharesExt(size_t n, EncShares& enc_sh)
    : R_(enc_sh.R), r_(enc_sh.r), Bs_(move(enc_sh.Bs)),
      Ds_(unique_ptr<vector<shared_ptr<ECPoint>>>(
          new vector<shared_ptr<ECPoint>>)) {
    Ds_->reserve(n);
}

DecShare::DecShare() {}

KeyPair::KeyPair() {}
