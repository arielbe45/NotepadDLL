#pragma once




BOOL AES_Encrypt(LPCVOID plaintextBuffer, DWORD plaintextSize, void** lpCiphertextBuffer, DWORD* lpCiphertextSize);
BOOL AES_Decrypt(LPCVOID ciphertextBuffer, DWORD ciphertextSize, void** lpPlaintextBuffer, DWORD* lpPlaintextSize);
BOOL DPAPI_Encrypt(LPCVOID plaintextBuffer, DWORD plaintextSize, void** lpCiphertextBuffer, DWORD* lpCiphertextSize);
BOOL DPAPI_Decrypt(LPCVOID ciphertextBuffer, DWORD ciphertextSize, void** lpPlaintextBuffer, DWORD* lpPlaintextSize);
BOOL Encrypt(LPCVOID plaintextBuffer, DWORD plaintextSize, void** lpCiphertextBuffer, DWORD* lpCiphertextSize);
BOOL Decrypt(LPCVOID ciphertextBuffer, DWORD ciphertextSize, void** lpPlaintextBuffer, DWORD* lpPlaintextSize);
