// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"
#include <Windows.h>
#include <TlHelp32.h>
#include "jni.h"

void Init();
HMODULE GetBaseAddr();
JNIEXPORT void JNICALL myLog
(JNIEnv* env, jclass clz, jstring str);

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    {
        Init();
    }
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

// mov rax, [addr]
// jmp rax

void Init()
{
    DWORD64 baseAddr = (DWORD64)GetBaseAddr();
    if (baseAddr == NULL)
    {
        MessageBoxA(NULL, "地址没取着。。。。。。", "鸽子智在线Mua Kendall", NULL);
        return;
    }
    DWORD64 wriAddr = baseAddr + 0x3080;

    /*
        MOV RAX, SS:[ADDR]
        JMP RAX
    */
    BYTE newBuf[] = {
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xE0, 0x90
    };;
    //7FFD66131240
    void* pLog = &myLog;
    DWORD64 pPLog = (DWORD64)&pLog;
    memcpy(newBuf + 2, (void*)pPLog, 8);
    DWORD oldProtect = 0;
    VirtualProtectEx(GetCurrentProcess(), (LPVOID)wriAddr, sizeof(newBuf), PAGE_READWRITE, &oldProtect);
    if (WriteProcessMemory(GetCurrentProcess(), (LPVOID)wriAddr, newBuf, sizeof(newBuf), NULL) == false)
    {
        MessageBoxA(NULL, "内存拒绝内入。。。", "鸽子智在线Mua Kendall", NULL);
        return;
    }
    VirtualProtectEx(GetCurrentProcess(), (LPVOID)wriAddr, sizeof(newBuf), oldProtect, &oldProtect);
   
}

JNIEXPORT void JNICALL myLog
(JNIEnv* env, jclass clz, jstring str)
{
    MessageBoxA(NULL, "Hooked", "Mua XiaoZhiSoC", NULL);
    // str <- 传入的路径
    // jstring != string <- 重点
     
    // 先把 jstring转string
    // 
    // 检测到他是网易的JAR文件
    // 恢复HOOK
    // 调用方法 (JNIEnv* env, jclass clz, jstring str)
    // 再HOOK

    // 如果不是
    // 直接返回 return
}

HMODULE GetBaseAddr()
{
    MODULEENTRY32 modEntry;
    ZeroMemory(&modEntry, sizeof(MODULEENTRY32));
    modEntry.dwSize = sizeof(MODULEENTRY32);
    HANDLE h = NULL;
    h = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
    if (h == NULL)
    {
        return NULL;
    }
    if (Module32First(h, &modEntry) == false)
    {
        return NULL;
    }
    while (true)
    {
        // MessageBox(NULL, modEntry.szModule, L"test", NULL);
        if (wcscmp(modEntry.szModule, L"api-ms-win-crt-utility-l1-1-1.dll") == 0)
        {
            return modEntry.hModule;
            // GetModuleHandle()
        }
        Module32Next(h, &modEntry);
        if (h == NULL)
            break;
    }
    return NULL;
}

