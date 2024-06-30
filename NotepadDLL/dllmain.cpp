// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include "encryption.h"
#include "prompt.h"
#include "logging.h"

#include <stdlib.h>
#include <psapi.h>

#pragma warning(disable : 4996)


const int MAX_FILE_PATH_SIZE = 100;


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


extern "C"
{
    __declspec(dllexport) BOOL DLLWriteFile(
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

    __declspec(dllexport) LPVOID DLLMapViewOfFile(
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
        memcpy(newBuffer, plaintextBuffer, plaintextSize);
        memset(((char*)newBuffer) + plaintextSize, 0, dwNumberOfBytesToMap - plaintextSize);
        free(plaintextBuffer);
        return newBuffer;
    }
}


void Init(HMODULE hModule) {
    /*ShowEncryptionKeyDialog(hModule);
    LogDebug("Encryption key: ");
    for (int i = 0; i < 32; i++) {
        LogDebug("%x", GetEncryptionKey()[i]);
    }
    LogDebug("\n");*/
}


BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        Init(hModule);
        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

