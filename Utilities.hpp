#ifndef __UTILITIES_H__
#define __UTILITIES_H__
#include <Windows.h>

typedef struct _PROCESS
{
    STARTUPINFOA stinfo = { 0 };
    PROCESS_INFORMATION pinfo = { 0 };
}PROCESS;

typedef enum _ARCH
{
    ARCH_NULL = 0,
    x86 = 0x20,
    x64 = 0x40,
} ARCH;

PROCESS* SpawnDebugProcess(const char* path_to_exe);
ARCH GetArchitecture(char* filename);

#endif //__UTILITIES_H__
