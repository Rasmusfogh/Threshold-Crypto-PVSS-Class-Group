#include "datatype.hpp"

using namespace DATATYPE;

EncShares::EncShares(size_t n) {

    Bs_ = unique_ptr<vector<shared_ptr<QFI>>>(new vector<shared_ptr<QFI>>);
    Bs_->reserve(n);
    generate_n(back_inserter(*Bs_), n,
        [] { return shared_ptr<QFI>(new QFI()); });
}

EncSharesExt::EncSharesExt(size_t n, BaseEncShares& enc_sh)
    : Ds_(unique_ptr<vector<shared_ptr<ECPoint>>>(
          new vector<shared_ptr<ECPoint>>)) {

    Ds_->reserve(n);
    r_ = enc_sh.r_;
    R_ = enc_sh.R_;
    Bs_ = move(enc_sh.Bs_);
}

EncSharesExt::EncSharesExt(BaseEncShares& enc_sh,
    unique_ptr<vector<shared_ptr<ECPoint>>> Ds, unique_ptr<NizkExtSH> pf) {

    r_ = enc_sh.r_;
    R_ = enc_sh.R_;
    Bs_ = move(enc_sh.Bs_);
    Ds_ = move(Ds);
    pf_ = move(pf);
}

EncSharesResh::EncSharesResh(BaseEncShares& enc_sh) {
    r_ = enc_sh.r_;
    R_ = enc_sh.R_;
    Bs_ = move(enc_sh.Bs_);
}

EncSharesResh::EncSharesResh(BaseEncShares& enc_sh, unique_ptr<NizkResh> pf) {
    r_ = enc_sh.r_;
    R_ = enc_sh.R_;
    Bs_ = move(enc_sh.Bs_);
    pf_ = move(pf);
}

DecShare::DecShare() {}