// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"

#define DLL_EXPORT

#include "dllmain.h"
#include "prompt.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>
#include <string.h>
#include <psapi.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <commdlg.h>

#pragma warning(disable : 4996)



extern "C"
{
    const int MAX_FILE_PATH_SIZE = 100;
    const char LOG_FILE[] = "output.txt";

    //const unsigned char AES_DEFAULT_KEY[33] = "\xd8\xa8\x53\x70\x3b\xa4\xb8\x68\x0d\x6f\x9a\x2c\x0e\x70\x87\xb8\x2d\xfb\x8e\xae\xd4\x16\x43\xe1\x3b\x1e\x1c\xb8\x35\x6a\xdc\xae";


    BOOL Encrypt(LPCVOID plaintextBuffer, DWORD plaintextSize, void** lpCiphertextBuffer, DWORD* lpCiphertextSize) {
        if (!plaintextBuffer || !lpCiphertextBuffer || !lpCiphertextSize) {
            return FALSE;
        }

        // Calculate the size of the padded buffer
        DWORD paddedSize = ((plaintextSize + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;

        // Allocate memory for ciphertext
        unsigned char* ciphertextBuffer = (unsigned char*)malloc(paddedSize + AES_BLOCK_SIZE);
        if (!ciphertextBuffer) {
            return FALSE;
        }

        // Generate random IV
        unsigned char iv[AES_BLOCK_SIZE];
        if (!RAND_bytes(iv, AES_BLOCK_SIZE)) {
            free(ciphertextBuffer);
            return FALSE;
        }

        // Copy IV to the beginning of the ciphertext
        memcpy(ciphertextBuffer, iv, AES_BLOCK_SIZE);

        // Initialize AES encryption context
        AES_KEY enc_key;
        AES_set_encrypt_key(GetEncryptionKey(), 256, &enc_key);

        // Encrypt the plaintext
        AES_cbc_encrypt((unsigned char*)plaintextBuffer, ciphertextBuffer + AES_BLOCK_SIZE, paddedSize, &enc_key, iv, AES_ENCRYPT);

        *lpCiphertextBuffer = ciphertextBuffer;
        *lpCiphertextSize = paddedSize + AES_BLOCK_SIZE;

        return TRUE;
    }

    BOOL Decrypt(LPCVOID ciphertextBuffer, DWORD ciphertextSize, void** lpPlaintextBuffer, DWORD* lpPlaintextSize) {
        if (!ciphertextBuffer || !lpPlaintextBuffer || !lpPlaintextSize) {
            return FALSE;
        }

        if (ciphertextSize < AES_BLOCK_SIZE) {
            return FALSE;
        }

        // Extract IV from the beginning of the ciphertext
        unsigned char iv[AES_BLOCK_SIZE];
        memcpy(iv, ciphertextBuffer, AES_BLOCK_SIZE);

        // Calculate the size of the padded plaintext
        DWORD paddedSize = ciphertextSize - AES_BLOCK_SIZE;

        // Allocate memory for plaintext
        unsigned char* plaintextBuffer = (unsigned char*)malloc(paddedSize);
        if (!plaintextBuffer) {
            return FALSE;
        }

        // Initialize AES decryption context
        AES_KEY dec_key;
        AES_set_decrypt_key(GetEncryptionKey(), 256, &dec_key);

        // Decrypt the ciphertext
        AES_cbc_encrypt((unsigned char*)ciphertextBuffer + AES_BLOCK_SIZE, plaintextBuffer, paddedSize, &dec_key, iv, AES_DECRYPT);

        *lpPlaintextBuffer = plaintextBuffer;
        *lpPlaintextSize = paddedSize;

        return TRUE;
    }


    void LogDebug(const char* fmt, ...) {
        // Open the file in append mode
        FILE* file;
        if (fopen_s(&file, LOG_FILE, "a") != 0) {
            perror("Failed to open log file");
            return;
        }

        // Initialize the variable argument list
        va_list args;
        va_start(args, fmt);

        // Write the formatted string to the file
        vfprintf(file, fmt, args);

        // Clean up the variable argument list
        va_end(args);

        // Close the file
        fclose(file);
    }


    void LogError(const char* fmt, ...) {
        // Get the last error message
        DWORD errorMessageID = GetLastError();
        char errorMessage[256];
        if (errorMessageID != 0) {
            FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                NULL, errorMessageID, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                errorMessage, sizeof(errorMessage), NULL);
        }
        else {
            strcpy_s(errorMessage, sizeof(errorMessage), "No error message available");
        }

        // Initialize the variable argument list
        va_list args;
        va_start(args, fmt);

        // Buffer to store the formatted message
        char buffer[1024];
        vsnprintf(buffer, sizeof(buffer), fmt, args);

        // Clean up the variable argument list
        va_end(args);

        // Log the error message with the prefix "ERROR: " and the last error message
        LogDebug("ERROR: %s: %s\n", buffer, errorMessage);
    }

    BOOL EndsWith(const char* str, const char* suffix) {
        size_t str_len = strlen(str);
        size_t suffix_len = strlen(suffix);

        // Check if the string is at least as long as the suffix
        if (str_len < suffix_len) {
            return FALSE;
        }

        // Compare the end of the string with the suffix
        return strcmp(str + str_len - suffix_len, suffix) == 0;
    }

    BOOL CheckFilenameEncrypted(const char* filePath) {
        return EndsWith(filePath, ".txts");
    }

    BOOL IsFileEncrypted(HANDLE hFile) {
        char filePath[MAX_FILE_PATH_SIZE];
        DWORD filePathLength = GetFinalPathNameByHandleA(hFile, filePath, sizeof(filePath), FILE_NAME_NORMALIZED);
        if (filePathLength == 0) {
            LogError("Error reading file path");
            return FALSE;
        }
        filePath[sizeof(filePath) - 1] = NULL;
        BOOL encrypted = CheckFilenameEncrypted(filePath);
        if (encrypted) {
            LogDebug("File path: %s is encrypted\n", filePath);
        }
        else {
            LogDebug("File path: %s isn't encrypted\n", filePath);
        }
        return encrypted;
    }

    BOOL IsMappedFileEncrypted(LPVOID address) {

        // Get the current process handle
        HANDLE hProcess = GetCurrentProcess();

        char filePath[MAX_FILE_PATH_SIZE];

        if (!GetMappedFileNameA(hProcess, address, filePath, sizeof(filePath))) {
            LogError("Error reading mapped file path");
            return FALSE;
        }
        filePath[sizeof(filePath) - 1] = NULL;
        BOOL encrypted = CheckFilenameEncrypted(filePath);
        if (encrypted) {
            LogDebug("File path: %s is encrypted\n", filePath);
        }
        else {
            LogDebug("File path: %s isn't encrypted\n", filePath);
        }
        return encrypted;
    }

    DECLDIR void Function() {
        LogDebug("Hello from DLL!\n");
    }

    DECLDIR BOOL DLLWriteFile(
        HANDLE       hFile,
        LPCVOID      lpBuffer,
        DWORD        nNumberOfBytesToWrite,
        LPDWORD      lpNumberOfBytesWritten,
        LPOVERLAPPED lpOverlapped
    ) {
        LogDebug("Writing to file!\n");
        if (!IsFileEncrypted(hFile)) {
            return WriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);
        }

        LPVOID ciphertextBuffer;
        DWORD ciphertextSize;

        if (!Encrypt(lpBuffer, nNumberOfBytesToWrite, &ciphertextBuffer, &ciphertextSize)) {
            LogError("Error encrypting file");
            return FALSE;
        }
        
        *lpNumberOfBytesWritten = nNumberOfBytesToWrite;
        return WriteFile(hFile, ciphertextBuffer, ciphertextSize, NULL, lpOverlapped);
    }

    DECLDIR BOOL DLLReadFile(
        HANDLE       hFile,
        LPVOID       lpBuffer,
        DWORD        nNumberOfBytesToRead,
        LPDWORD      lpNumberOfBytesRead,
        LPOVERLAPPED lpOverlapped
    ) {
        LogDebug("Reading from file!\n");
        return ReadFile(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);
    }

    DECLDIR LPVOID DLLMapViewOfFile(
        HANDLE hFileMappingObject,
        DWORD  dwDesiredAccess,
        DWORD  dwFileOffsetHigh,
        DWORD  dwFileOffsetLow,
        SIZE_T dwNumberOfBytesToMap
    ) {
        LogDebug("Map view of file: dwDesiredAccess=%x, dwFileOffsetHigh=%x, dwFileOffsetLow=%x, dwNumberOfBytesToMap=%x\n",
            dwDesiredAccess, dwFileOffsetHigh, dwFileOffsetLow, dwNumberOfBytesToMap);

        LPVOID ciphertextMmap = MapViewOfFile(hFileMappingObject, dwDesiredAccess, dwFileOffsetHigh, dwFileOffsetLow, dwNumberOfBytesToMap);
        LogDebug("MMAP: %p\n", ciphertextMmap);
        if (!IsMappedFileEncrypted(ciphertextMmap)) {
            return ciphertextMmap;
        }

        if (ciphertextMmap == NULL) {
            return NULL;
        }

        LPVOID plaintextBuffer;
        DWORD plaintextSize;

        if (!Decrypt(ciphertextMmap, dwNumberOfBytesToMap, &plaintextBuffer, &plaintextSize)) {
            LogError("Error in decrypting file");
            return NULL;
        }

        char* newBuffer = (char*)malloc(dwNumberOfBytesToMap);
        if (!newBuffer) {
            LogError("Error in decrypting file");
            return NULL;
        }

        LogDebug("Decrypting file: dwNumberOfBytesToMap=%x, plaintextSize=%x\n", dwNumberOfBytesToMap, plaintextSize);
        plaintextSize = strlen((LPCSTR)plaintextBuffer);
        memcpy(newBuffer, plaintextBuffer, plaintextSize);
        memset(((char*)newBuffer) + plaintextSize, 0, dwNumberOfBytesToMap - plaintextSize);
        free(plaintextBuffer);
        return newBuffer;
    }

    DECLDIR BOOL DLLUnmapViewOfFile(
        LPCVOID lpBaseAddress
    ) {
        LogDebug("Unmap view of file!\n");
        return UnmapViewOfFile(lpBaseAddress);
    }

    DECLDIR BOOL DLLGetOpenFileNameW(
        LPOPENFILENAMEW unnamedParam1
    ) {
        LogDebug("Get open file name!\n");
        return GetOpenFileNameW(unnamedParam1);
    }
}


BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        Function();
        ShowEncryptionKeyDialog(hModule);
        LogDebug("Encryption key: ");
        for (int i = 0; i < 32; i++) {
            LogDebug("%x", GetEncryptionKey()[i]);
        }
        LogDebug("\n");
        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

