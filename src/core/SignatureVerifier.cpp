#include "SignatureVerifier.h"
#include <Windows.h>
#include <Softpub.h>
#include <wincrypt.h>
#include <wintrust.h>
#include <vector>

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")

// Достаём CN= из subject поля сертификата.
static std::wstring ExtractSubjectName(PCCERT_CONTEXT cert) {
    if (!cert) return {};

    DWORD len = CertGetNameStringW(
        cert, CERT_NAME_SIMPLE_DISPLAY_TYPE,
        0, nullptr, nullptr, 0);
    if (len <= 1) return {};

    std::wstring out(len, L'\0');
    CertGetNameStringW(
        cert, CERT_NAME_SIMPLE_DISPLAY_TYPE,
        0, nullptr, out.data(), len);

    // CertGetNameString включает завершающий \0 — убираем
    if (!out.empty() && out.back() == L'\0') out.pop_back();
    return out;
}

// Извлекает имя издателя из подписи файла.
static std::wstring GetPublisherName(const std::wstring& filePath) {
    HCERTSTORE hStore = nullptr;
    HCRYPTMSG  hMsg   = nullptr;
    DWORD      encoding = 0, contentType = 0, formatType = 0;

    BOOL ok = CryptQueryObject(
        CERT_QUERY_OBJECT_FILE,
        filePath.c_str(),
        CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
        CERT_QUERY_FORMAT_FLAG_BINARY,
        0,
        &encoding,
        &contentType,
        &formatType,
        &hStore,
        &hMsg,
        nullptr);

    if (!ok || !hMsg || !hStore) {
        if (hStore) CertCloseStore(hStore, 0);
        if (hMsg)   CryptMsgClose(hMsg);
        return {};
    }

    // Достаём signer info
    DWORD signerInfoSize = 0;
    CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, nullptr, &signerInfoSize);
    if (signerInfoSize == 0) {
        CertCloseStore(hStore, 0);
        CryptMsgClose(hMsg);
        return {};
    }

    std::vector<BYTE> signerInfoBuf(signerInfoSize);
    if (!CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0,
                          signerInfoBuf.data(), &signerInfoSize)) {
        CertCloseStore(hStore, 0);
        CryptMsgClose(hMsg);
        return {};
    }

    PCMSG_SIGNER_INFO signer = (PCMSG_SIGNER_INFO)signerInfoBuf.data();

    // Ищем сертификат signer'а в store
    CERT_INFO ci{};
    ci.Issuer       = signer->Issuer;
    ci.SerialNumber = signer->SerialNumber;

    PCCERT_CONTEXT cert = CertFindCertificateInStore(
        hStore,
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        0,
        CERT_FIND_SUBJECT_CERT,
        &ci,
        nullptr);

    std::wstring publisher;
    if (cert) {
        publisher = ExtractSubjectName(cert);
        CertFreeCertificateContext(cert);
    }

    CertCloseStore(hStore, 0);
    CryptMsgClose(hMsg);
    return publisher;
}

SignatureInfo SignatureVerifier::Verify(const std::filesystem::path& path) {
    SignatureInfo info;

    std::wstring filePath = path.wstring();

    // Готовим структуры для WinVerifyTrust
    WINTRUST_FILE_INFO fileInfo{};
    fileInfo.cbStruct        = sizeof(fileInfo);
    fileInfo.pcwszFilePath   = filePath.c_str();
    fileInfo.hFile           = nullptr;
    fileInfo.pgKnownSubject  = nullptr;

    GUID policyGuid = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    WINTRUST_DATA wd{};
    wd.cbStruct            = sizeof(wd);
    wd.dwUIChoice          = WTD_UI_NONE;
    wd.fdwRevocationChecks = WTD_REVOKE_NONE;
    wd.dwUnionChoice       = WTD_CHOICE_FILE;
    wd.pFile               = &fileInfo;
    wd.dwStateAction       = WTD_STATEACTION_VERIFY;
    wd.dwProvFlags         = WTD_SAFER_FLAG;

    LONG status = WinVerifyTrust(nullptr, &policyGuid, &wd);

    info.valid = (status == ERROR_SUCCESS);

    // Закрываем state action
    wd.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(nullptr, &policyGuid, &wd);

    // Если подпись валидна — достаём издателя.
    if (info.valid) {
        info.publisher = GetPublisherName(filePath);
    }

    return info;
}
