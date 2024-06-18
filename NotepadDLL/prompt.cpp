#include "pch.h"
#include "prompt.h"

// Constants for window dimensions and control positions
#define WINDOW_WIDTH 600
#define WINDOW_HEIGHT 200

#define EDITBOX_X 10
#define EDITBOX_Y 20
#define EDITBOX_WIDTH (WINDOW_WIDTH - 2 * (EDITBOX_X + 10))
#define EDITBOX_HEIGHT 30

#define BUTTON_Y 70
#define BUTTON_WIDTH 100
#define BUTTON_HEIGHT 40
#define BUTTON_X ((WINDOW_WIDTH - BUTTON_WIDTH) / 2 - 10)

#define AES_KEY_SIZE 32


// Global variables
HINSTANCE hInst;
HWND hEdit;
BYTE encryptionKey[AES_KEY_SIZE] = { 0 };


// Function to create and display the window
void ShowEncryptionKeyDialog(HINSTANCE hInstance) {
    WNDCLASSEX wcex;
    HWND hWnd;
    MSG msg;
    BOOL bRet;

    hInst = hInstance;

    // Register window class
    wcex.cbSize = sizeof(WNDCLASSEX);
    wcex.style = CS_HREDRAW | CS_VREDRAW;
    wcex.lpfnWndProc = WndProc;
    wcex.cbClsExtra = 0;
    wcex.cbWndExtra = 0;
    wcex.hInstance = hInstance;
    wcex.hIcon = LoadIcon(NULL, IDI_APPLICATION);
    wcex.hCursor = LoadCursor(NULL, IDC_ARROW);
    wcex.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wcex.lpszMenuName = NULL;
    wcex.lpszClassName = L"EncryptionKeyClass";
    wcex.hIconSm = LoadIcon(NULL, IDI_APPLICATION);

    RegisterClassEx(&wcex);

    // Create the window
    hWnd = CreateWindow(L"EncryptionKeyClass", L"Encryption Key", WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, 0, WINDOW_WIDTH, WINDOW_HEIGHT, NULL, NULL, hInstance, NULL);

    ShowWindow(hWnd, SW_SHOW);
    UpdateWindow(hWnd);

    // Message loop
    while ((bRet = GetMessage(&msg, NULL, 0, 0)) != 0) {
        if (bRet == -1) {
            // Handle the error and exit
            return;
        }
        else {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
    }
}

// Function to convert hex character to byte
BYTE HexCharToByte(char hex) {
    if (hex >= '0' && hex <= '9') {
        return hex - '0';
    }
    else if (hex >= 'A' && hex <= 'F') {
        return hex - 'A' + 10;
    }
    else if (hex >= 'a' && hex <= 'f') {
        return hex - 'a' + 10;
    }
    return 0; // Invalid character
}

// Function to convert two hex characters to a byte
BYTE HexToByte(LPCWCHAR hex) {
    return (HexCharToByte(hex[0]) << 4) | HexCharToByte(hex[1]);
}

// Function to set the encryption key after window is closed
void SetEncryptionKey(void) {
    WCHAR hexKey[256] = { 0 };
    GetWindowText(hEdit, hexKey, sizeof(hexKey) / sizeof(hexKey[0]));

    for (int i = 0; i < AES_KEY_SIZE; ++i) {
        encryptionKey[i] = HexToByte(hexKey + 2 * i);
    }
}

BYTE* GetEncryptionKey(void) {
    return encryptionKey;
}

// Window procedure function
LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam) {
    switch (message) {
    case WM_CREATE:
        // Create the edit control
        hEdit = CreateWindowEx(WS_EX_CLIENTEDGE, L"EDIT", L"",
            WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL,
            EDITBOX_X, EDITBOX_Y, EDITBOX_WIDTH, EDITBOX_HEIGHT, hWnd, NULL, hInst, NULL);
        // Create the submit button
        CreateWindow(L"BUTTON", L"Submit", WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,
            BUTTON_X, BUTTON_Y, BUTTON_WIDTH, BUTTON_HEIGHT, hWnd, (HMENU)1, hInst, NULL);
        break;
    case WM_COMMAND:
        if (LOWORD(wParam) == 1) { // Submit button clicked
            SetEncryptionKey();
            PostQuitMessage(0); // Exit the message loop
            DestroyWindow(hWnd); // Destroy the window
        }
        break;
    case WM_DESTROY:
        PostQuitMessage(0);
        break;
    default:
        return DefWindowProc(hWnd, message, wParam, lParam);
    }
    return 0;
}