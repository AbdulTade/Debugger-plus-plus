
#ifndef __ERROR_H__
#define __ERROR_H__

#include <Windows.h>

#define ERROR_COLOR   "\033[91m"
#define SUCCESS_COLOR "\033[92m"
#define WARNING_COLOR "\033[93m"
#define RESET_COLOR   "\033[0m"

void WriteError(const char* _Msg);
void DieWithError(const char* _Msg, int iExitCode);
void WriteOutput(const char* _Msg);
void WriteOutputFormatted(const char* fmt, ...);

#endif //__ERROR_H__