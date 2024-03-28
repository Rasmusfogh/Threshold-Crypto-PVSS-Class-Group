#include <datatype.hpp>

using namespace DATATYPE;

EncShares::EncShares(size_t n) 
{
    Bs = unique_ptr<vector<unique_ptr<QFI>>>
        (new vector<unique_ptr<QFI>>);

    Bs->reserve(n);
    generate_n(back_inserter(*Bs), n, [] 
        {return unique_ptr<QFI>(new QFI()); });
}

EncSharesExt::EncSharesExt(size_t n, const ECGroup& ec_group_) 
{
    Ds_ = unique_ptr<vector<unique_ptr<ECPoint>>>
        (new vector<unique_ptr<ECPoint>>);

    Ds_->reserve(n);
    generate_n(back_inserter(*Ds_), n, [&] 
        {return unique_ptr<ECPoint>(new ECPoint(ec_group_)); });
}

DecShare::DecShare() {}
