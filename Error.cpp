#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include "Error.hpp"

void WriteError(const char* _Msg)
{
    fprintf(stderr, "%s[-] %s %s\n", ERROR_COLOR, _Msg, RESET_COLOR);
    return;
}

void DieWithError(const char* _Msg, int iExitCode)
{
    WriteError(_Msg);
    ExitProcess(iExitCode);
}

void WriteOutput(const char* _Msg)
{
    fprintf(stderr, "%s  [+] %s %s", SUCCESS_COLOR, _Msg, RESET_COLOR);
}

void WriteOutputFormatted(const char* fmt, ...)
{
    //char* ext_fmt = new char[strlen(fmt) + 100];
    printf("%s",SUCCESS_COLOR);
    //snprintf(ext_fmt, strlen(fmt) + 100, "%s[+] %s %s", SUCCESS_COLOR, fmt, RESET_COLOR);
    va_list args;
    va_start(args, fmt);
    vprintf_s(fmt, args);
    va_end(args);
    printf("%s",RESET_COLOR);
}