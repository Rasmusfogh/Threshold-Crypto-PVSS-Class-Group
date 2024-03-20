#include <datatype.hpp>

using namespace DATATYPE;

EncShares::EncShares(size_t n) : Bs(n) {}
EncSharesExt::EncSharesExt(size_t n) : Bs(n), Ds(n) {}

DecShare::DecShare() {}
