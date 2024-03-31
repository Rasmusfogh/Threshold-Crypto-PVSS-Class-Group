#include "bicycl.hpp"
#include "qclpvss_utils.hpp"
#include <memory>

using namespace BICYCL;
using namespace OpenSSL;
using namespace UTILS;
using namespace std;

template <>
void OpenSSL::HashAlgo::hash(const vector<unique_ptr<QFI>>& v) {
    for (const auto& _ : v)
        hash(*_);
}

template <>
void OpenSSL::HashAlgo::hash(const vector<unique_ptr<const PublicKey>>& v) {
    for (const auto& _ : v)
        hash(_->get());
}

template <>
void OpenSSL::HashAlgo::hash(const vector<QFI>& v) {
    for (const auto& _ : v)
        hash(_);
}

template <>
void OpenSSL::HashAlgo::hash(const vector<Mpz>& v) {
    for (const auto& _ : v)
        hash(_);
}

template <>
void OpenSSL::HashAlgo::hash(
    const pair<const vector<unique_ptr<ECPoint>>&, const ECGroup&>& v) {
    for (const auto& ec : v.first)
        hash(ECPointGroupCRefPair(*ec, v.second));
}
