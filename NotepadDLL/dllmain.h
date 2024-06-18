#pragma once

#ifdef DLL_EXPORT
#define DECLDIR __declspec(dllexport)
#else
#define DECLDIR __declspec(dllimport)
#endif

extern "C"
{
	DECLDIR void Function();

    DECLDIR BOOL DLLWriteFile(
        HANDLE       hFile,
        LPCVOID      lpBuffer,
        DWORD        nNumberOfBytesToWrite,
        LPDWORD      lpNumberOfBytesWritten,
        LPOVERLAPPED lpOverlapped
    );

    DECLDIR BOOL DLLReadFile(
        HANDLE       hFile,
        LPVOID       lpBuffer,
        DWORD        nNumberOfBytesToRead,
        LPDWORD      lpNumberOfBytesRead,
        LPOVERLAPPED lpOverlapped
    );
}