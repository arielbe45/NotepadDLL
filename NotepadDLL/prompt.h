#pragma once

// Function prototypes
LRESULT CALLBACK WndProc(HWND, UINT, WPARAM, LPARAM);
void ShowEncryptionKeyDialog(HINSTANCE hInstance);
void SetEncryptionKey(void);
BYTE *GetEncryptionKey(void);
BYTE HexCharToByte(char hex);
BYTE HexToByte(LPCWCHAR hex);