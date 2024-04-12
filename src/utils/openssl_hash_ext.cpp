#include "qclpvss_utils.hpp"
#include <bicycl.hpp>
#include <memory>

using namespace BICYCL;
using namespace OpenSSL;
using namespace std;
using namespace UTILS;

template <>
void OpenSSL::HashAlgo::hash(const vector<shared_ptr<QFI>>& v) {
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
    const pair<const vector<shared_ptr<ECPoint>>&, const ECGroup&>& v) {
    for (const auto& ec : v.first)
        hash(ECPointGroupCRefPair(*ec, v.second));
}

template <>
void OpenSSL::HashAlgo::hash(const PublicKey& v) {
    hash(v.get());
}

template <>
void OpenSSL::HashAlgo::hash(const vector<vector<QFI>>& v) {
    for (const auto& _ : v)
        hash(_);
}