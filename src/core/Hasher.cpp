#include "Hasher.h"
#include <Windows.h>
#include <bcrypt.h>
#include <fstream>
#include <vector>

#pragma comment(lib, "bcrypt.lib")

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0)
#endif

static std::string HexLower(const unsigned char* data, size_t len) {
    static const char hex[] = "0123456789abcdef";
    std::string out(len * 2, '0');
    for (size_t i = 0; i < len; ++i) {
        out[2*i]     = hex[(data[i] >> 4) & 0xF];
        out[2*i + 1] = hex[ data[i]       & 0xF];
    }
    return out;
}

std::optional<std::string> Hasher::Sha256File(const std::filesystem::path& path) {
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0)
            != STATUS_SUCCESS) {
        return std::nullopt;
    }

    DWORD cbObject = 0, cb = 0;
    BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH,
                      (PUCHAR)&cbObject, sizeof(cbObject), &cb, 0);

    DWORD cbHash = 0;
    BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH,
                      (PUCHAR)&cbHash, sizeof(cbHash), &cb, 0);

    std::vector<UCHAR> obj(cbObject);
    std::vector<UCHAR> hash(cbHash);

    BCRYPT_HASH_HANDLE hHash = nullptr;
    if (BCryptCreateHash(hAlg, &hHash, obj.data(), cbObject, nullptr, 0, 0)
            != STATUS_SUCCESS) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return std::nullopt;
    }

    std::ifstream f(path, std::ios::binary);
    if (!f) {
        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return std::nullopt;
    }

    std::vector<char> buf(64 * 1024);
    while (f) {
        f.read(buf.data(), (std::streamsize)buf.size());
        std::streamsize n = f.gcount();
        if (n <= 0) break;
        if (BCryptHashData(hHash, (PUCHAR)buf.data(), (ULONG)n, 0)
                != STATUS_SUCCESS) {
            BCryptDestroyHash(hHash);
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return std::nullopt;
        }
    }

    BCryptFinishHash(hHash, hash.data(), cbHash, 0);
    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    return HexLower(hash.data(), hash.size());
}
