#include "pch.h"
#include "logging.h"

#include <stdio.h>
#include <stdarg.h>
#include <errno.h>


const char LOG_FILE[] = "output.txt";


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

