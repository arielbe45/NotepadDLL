#include "pch.h"
#include "encryption.h"
#include "prompt.h"
#include "logging.h"

#include <psapi.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <commdlg.h>
#include <dpapi.h>
#include <stdlib.h>

#pragma warning(disable : 4996)


typedef struct {
    size_t size;
    BYTE data[1];
} sizedBuffer;


BOOL Encrypt(LPCVOID plaintextBuffer, DWORD plaintextSize, void** lpCiphertextBuffer, DWORD* lpCiphertextSize) {
    if (!plaintextBuffer || !lpCiphertextBuffer || !lpCiphertextSize) {
        return FALSE;
    }

    sizedBuffer *sizedPlaintextBuffer = (sizedBuffer *)malloc(plaintextSize + sizeof(size_t) + 1);
    if (!sizedPlaintextBuffer) {
        LogError("Error in malloc");
        return FALSE;
    }

    sizedPlaintextBuffer->size = plaintextSize;
    memcpy(&sizedPlaintextBuffer->data, plaintextBuffer, plaintextSize);
    sizedPlaintextBuffer->data[plaintextSize] = NULL;

    LogDebug("Encrypting file: %x, %s\n", sizedPlaintextBuffer->size, sizedPlaintextBuffer->data);

    BOOL result = DPAPI_Encrypt((LPVOID)sizedPlaintextBuffer, plaintextSize + sizeof(size_t), lpCiphertextBuffer, lpCiphertextSize);
    free(sizedPlaintextBuffer);
    return result;
}


BOOL Decrypt(LPCVOID ciphertextBuffer, DWORD ciphertextSize, void** lpPlaintextBuffer, DWORD* lpPlaintextSize) {
    if (!ciphertextBuffer || !lpPlaintextBuffer || !lpPlaintextSize) {
        return FALSE;
    }
    sizedBuffer* sizedPlaintextBuffer;
    DWORD plaintextSize;

    if (!DPAPI_Decrypt(ciphertextBuffer, ciphertextSize, (void**) & sizedPlaintextBuffer, &plaintextSize)) {
        return FALSE;
    }

    *lpPlaintextBuffer = malloc(sizedPlaintextBuffer->size);
    if (!*lpPlaintextBuffer) {
        return FALSE;
    }

    memcpy(*lpPlaintextBuffer, sizedPlaintextBuffer->data, sizedPlaintextBuffer->size);
    *lpPlaintextSize = sizedPlaintextBuffer->size;
    LogDebug("Decrypting file: %x, %s\n", *lpPlaintextSize, *lpPlaintextBuffer);
    return TRUE;
}


BOOL AES_Encrypt(LPCVOID plaintextBuffer, DWORD plaintextSize, void** lpCiphertextBuffer, DWORD* lpCiphertextSize) {
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


BOOL AES_Decrypt(LPCVOID ciphertextBuffer, DWORD ciphertextSize, void** lpPlaintextBuffer, DWORD* lpPlaintextSize) {
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


BOOL DPAPI_Encrypt(LPCVOID plaintextBuffer, DWORD plaintextSize, void** lpCiphertextBuffer, DWORD* lpCiphertextSize) {
    DATA_BLOB ciphertextBlob;
    DATA_BLOB plaintextBlob;

    plaintextBlob.cbData = plaintextSize;
    plaintextBlob.pbData = (BYTE*)plaintextBuffer;

    if (CryptProtectData(
        &plaintextBlob,
        NULL,
        NULL,                 // Optional entropy
        NULL,                 // Reserved
        NULL,                 // Here, the optional prompt structure is not used
        0,
        &ciphertextBlob))
    {
        *lpCiphertextSize = ciphertextBlob.cbData;
        *lpCiphertextBuffer = ciphertextBlob.pbData;
        return TRUE;
    }
    else
    {
        LogError("Decryption error in DPAPI");
        return FALSE;
    }
}


BOOL DPAPI_Decrypt(LPCVOID ciphertextBuffer, DWORD ciphertextSize, void** lpPlaintextBuffer, DWORD* lpPlaintextSize) {
    DATA_BLOB ciphertextBlob;
    DATA_BLOB plaintextBlob;

    ciphertextBlob.cbData = ciphertextSize;
    ciphertextBlob.pbData = (BYTE*)ciphertextBuffer;

    if (CryptUnprotectData(
        &ciphertextBlob,
        NULL,
        NULL,                 // Optional entropy
        NULL,                 // Reserved
        NULL,                 // Here, the optional prompt structure is not used
        0,
        &plaintextBlob))
    {
        *lpPlaintextSize = plaintextBlob.cbData;
        *lpPlaintextBuffer = plaintextBlob.pbData;
        return TRUE;
    }
    else
    {
        LogError("Decryption error in DPAPI");
        return FALSE;
    }
}
