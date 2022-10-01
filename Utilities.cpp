#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include "Error.hpp"

#define WRITE_DEBUG_OUTPUT
#define MODULE_HANDLE   0x1
#define MODULE_FILENAME 0x2

typedef enum _ARCH
{
    ARCH_NULL = 0,
    x86 = 0x20,
    x64 = 0x40,
} ARCH;

typedef struct _PROCESS
{
    STARTUPINFOA stinfo = { 0 };
    PROCESS_INFORMATION pinfo = { 0 };
}PROCESS;

PROCESS* SpawnProcess(const char* path_to_exe)
{
    PROCESS* process = new PROCESS;
    process->stinfo.cb = sizeof(STARTUPINFOA);
    BOOL bSpawned;

    bSpawned = CreateProcessA(
        path_to_exe,
        NULL,
        NULL,
        NULL,
        FALSE,
        DEBUG_PROCESS,
        NULL,
        NULL,
        &process->stinfo,
        &process->pinfo
    );

    if (!bSpawned)
        return NULL;

    return process;
}

ARCH GetArchitecture(PVOID pData, DWORD InfoType)
{
    DWORD BinType = 0;
    if (InfoType & MODULE_HANDLE)
    {
        char* name = new char[MAX_PATH];
        GetModuleFileNameA((HMODULE)pData, name, MAX_PATH);
        GetBinaryTypeA(name, &BinType);
        delete[] name;
    }

    else if (InfoType & MODULE_FILENAME)
    {
        GetBinaryTypeA((LPCSTR)pData, &BinType);
    }

    else {
        WriteError("Unknown InfoType: Allowable types MODULE_FILENAME && MODULE_HANDLE");
    }

    switch (BinType)
    {
    case SCS_32BIT_BINARY:
        return x86;
    case SCS_64BIT_BINARY:
        return x64;
    default:
        return ARCH_NULL;
    }
}