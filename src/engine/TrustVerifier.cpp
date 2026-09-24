#include "TrustVerifier.h"

#include <Windows.h>
#include <SoftPub.h>
#include <WinTrust.h>
#include <mscat.h>
#include <wincrypt.h>

#include <algorithm>
#include <cwctype>
#include <mutex>
#include <unordered_map>
#include <vector>

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")

namespace TrustVerifier {
namespace {

std::wstring Lower(std::wstring s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](wchar_t c) { return static_cast<wchar_t>(std::towlower(c)); });
    return s;
}

// Издатель из состояния проверки: одинаково работает для встроенной
// и для каталожной подписи.
std::wstring PublisherFromState(HANDLE stateData) {
    CRYPT_PROVIDER_DATA* prov = WTHelperProvDataFromStateData(stateData);
    if (!prov) return {};
    CRYPT_PROVIDER_SGNR* signer = WTHelperGetProvSignerFromChain(prov, 0, FALSE, 0);
    if (!signer || signer->csCertChain == 0 || !signer->pasCertChain) return {};
    PCCERT_CONTEXT cert = signer->pasCertChain[0].pCert;
    if (!cert) return {};

    const DWORD len = CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0,
                                         nullptr, nullptr, 0);
    if (len <= 1) return {};
    std::wstring name(len, L'\0');
    CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, name.data(), len);
    while (!name.empty() && name.back() == L'\0') name.pop_back();
    return name;
}

// Общая часть: WinVerifyTrust с уже заполненным объединением и чтение
// издателя до закрытия состояния.
bool RunVerify(WINTRUST_DATA& wd, std::wstring* publisher) {
    GUID policy = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    wd.cbStruct            = sizeof(wd);
    wd.dwUIChoice          = WTD_UI_NONE;
    wd.fdwRevocationChecks = WTD_REVOKE_NONE;
    wd.dwStateAction       = WTD_STATEACTION_VERIFY;
    // Без сети: проверка не должна ходить за списками отзыва на каждый файл.
    wd.dwProvFlags         = WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_SAFER_FLAG;

    const LONG status = WinVerifyTrust(static_cast<HWND>(INVALID_HANDLE_VALUE), &policy, &wd);
    const bool ok = (status == ERROR_SUCCESS);
    if (ok && publisher) *publisher = PublisherFromState(wd.hWVTStateData);

    wd.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(static_cast<HWND>(INVALID_HANDLE_VALUE), &policy, &wd);
    return ok;
}

bool VerifyEmbedded(const std::wstring& path, std::wstring* publisher) {
    WINTRUST_FILE_INFO fi{};
    fi.cbStruct      = sizeof(fi);
    fi.pcwszFilePath = path.c_str();

    WINTRUST_DATA wd{};
    wd.dwUnionChoice = WTD_CHOICE_FILE;
    wd.pFile         = &fi;
    return RunVerify(wd, publisher);
}

bool VerifyCatalogWith(const std::wstring& path, const wchar_t* algorithm,
                       std::wstring* publisher)
{
    GUID driverAction = DRIVER_ACTION_VERIFY;
    HCATADMIN admin = nullptr;
    if (!CryptCATAdminAcquireContext2(&admin, &driverAction, algorithm, nullptr, 0))
        return false;

    HANDLE file = CreateFileW(path.c_str(), GENERIC_READ,
                              FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                              nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        CryptCATAdminReleaseContext(admin, 0);
        return false;
    }

    DWORD hashSize = 0;
    CryptCATAdminCalcHashFromFileHandle2(admin, file, &hashSize, nullptr, 0);
    std::vector<BYTE> hash(hashSize);
    bool ok = false;

    if (hashSize && CryptCATAdminCalcHashFromFileHandle2(admin, file, &hashSize, hash.data(), 0)) {
        HCATINFO info = CryptCATAdminEnumCatalogFromHash(admin, hash.data(), hashSize, 0, nullptr);
        if (info) {
            CATALOG_INFO ci{};
            ci.cbStruct = sizeof(ci);
            if (CryptCATCatalogInfoFromContext(info, &ci, 0)) {
                // Тег члена каталога — хэш в шестнадцатеричном виде.
                static const wchar_t hex[] = L"0123456789ABCDEF";
                std::wstring tag;
                for (BYTE b : hash) { tag += hex[b >> 4]; tag += hex[b & 0xF]; }

                WINTRUST_CATALOG_INFO wci{};
                wci.cbStruct             = sizeof(wci);
                wci.pcwszCatalogFilePath = ci.wszCatalogFile;
                wci.pcwszMemberFilePath  = path.c_str();
                wci.pcwszMemberTag       = tag.c_str();
                wci.pbCalculatedFileHash = hash.data();
                wci.cbCalculatedFileHash = hashSize;
                wci.hCatAdmin            = admin;

                WINTRUST_DATA wd{};
                wd.dwUnionChoice = WTD_CHOICE_CATALOG;
                wd.pCatalog      = &wci;
                ok = RunVerify(wd, publisher);
            }
            CryptCATAdminReleaseCatalogContext(admin, info, 0);
        }
    }

    CloseHandle(file);
    CryptCATAdminReleaseContext(admin, 0);
    return ok;
}

struct CacheEntry {
    ULONGLONG size = 0;
    FILETIME  written{};
    Result    result;
};

std::mutex g_cacheLock;
std::unordered_map<std::wstring, CacheEntry> g_cache;

} // namespace

bool IsTrustedVendor(const std::wstring& publisher) {
    static const std::vector<std::wstring> kVendors = {
        L"microsoft corporation", L"microsoft windows", L"microsoft windows publisher",
        L"microsoft windows hardware compatibility publisher",
        L"microsoft 3rd party application component", L"microsoft windows kits publisher",
        L"microsoft windows production pca 2011",
        L"google llc", L"google inc", L"mozilla corporation", L"apple inc.",
        L"nvidia corporation", L"intel corporation", L"advanced micro devices, inc.",
        L"advanced micro devices inc.", L"realtek semiconductor corp.",
        L"valve corp.", L"valve", L"epic games inc.", L"epic games, inc.",
        L"riot games, inc.", L"electronic arts, inc.", L"blizzard entertainment, inc.",
        L"opera norway as", L"brave software, inc.", L"discord inc.", L"telegram fz-llc",
        L"oracle america, inc.", L"oracle corporation", L"adobe inc.",
        L"adobe systems, incorporated", L"docker inc", L"github, inc.",
        L"jetbrains s.r.o.", L"python software foundation", L"openjs foundation",
        L"zoom video communications, inc.", L"spotify ab", L"yandex llc",
        L"ao kaspersky lab", L"kaspersky lab jsc", L"eset, spol. s r.o.",
        L"avast software s.r.o.", L"bitdefender srl", L"malwarebytes inc.",
        L"malwarebytes corporation", L"logitech inc", L"razer usa ltd.", L"dell inc",
        L"hp inc.", L"lenovo", L"asustek computer inc.", L"micro-star international co., ltd.",
        L"giga-byte technology co., ltd.", L"vmware, inc.", L"meta platforms, inc.",
        L"slack technologies, llc", L"notepad++", L"the qt company oy",
    };
    const std::wstring p = Lower(publisher);
    return std::find(kVendors.begin(), kVendors.end(), p) != kVendors.end();
}

Result Check(const std::wstring& path) {
    WIN32_FILE_ATTRIBUTE_DATA attr{};
    if (!GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &attr)) return {};
    const ULONGLONG size = (static_cast<ULONGLONG>(attr.nFileSizeHigh) << 32) | attr.nFileSizeLow;
    const std::wstring key = Lower(path);

    {
        std::lock_guard<std::mutex> lock(g_cacheLock);
        auto it = g_cache.find(key);
        if (it != g_cache.end() && it->second.size == size &&
            CompareFileTime(&it->second.written, &attr.ftLastWriteTime) == 0)
        {
            return it->second.result;
        }
    }

    Result r;
    std::wstring publisher;
    if (VerifyEmbedded(path, &publisher)) {
        r.signedValid = true;
    } else if (VerifyCatalogWith(path, BCRYPT_SHA256_ALGORITHM, &publisher) ||
               VerifyCatalogWith(path, nullptr, &publisher)) {
        // Старые каталоги считаются по SHA-1 — отсюда вторая попытка.
        r.signedValid = true;
        r.catalog     = true;
    }
    r.publisher     = publisher;
    r.trustedVendor = r.signedValid && IsTrustedVendor(publisher);

    std::lock_guard<std::mutex> lock(g_cacheLock);
    if (g_cache.size() > 20000) g_cache.clear();
    g_cache[key] = { size, attr.ftLastWriteTime, r };
    return r;
}

} // namespace TrustVerifier
