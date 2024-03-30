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

EncSharesExt::EncSharesExt(size_t n) 
{
    Ds_ = unique_ptr<vector<unique_ptr<ECPoint>>>
        (new vector<unique_ptr<ECPoint>>);

    Ds_->reserve(n);
}

DecShare::DecShare() {}
