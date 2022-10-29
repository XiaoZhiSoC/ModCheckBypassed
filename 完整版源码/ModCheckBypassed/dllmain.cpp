// dllmain.cpp : 定义 DLL 应用程序的入口点。

#include "pch.h"
#include "jni.h"
#include <string>
#include <psapi.h>
using namespace std;

DWORD64 lpStartAddr = 0;

JNIEnv* jni_env;
jobject jobject_obj;

typedef void (*pLog)(JNIEnv* env, jobject obj, jstring path);

void JNICALL HookLog(JNIEnv* env, jobject obj, jstring path);

UINT64 GetFunAddrByName(HANDLE hProcess, char* ModName, char* FunName);
PVOID GetProcessMoudleBase(HANDLE hProcess, char* moduleName);
string jstring2str(JNIEnv* env, jstring jstr);
DWORD preInit(LPVOID value);
void start();
void asmHook();
void asmRecovery();
void callLog(string path);
bool isFrist = false;
void addJar();

BYTE buf_hook[] =
{
    0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xE0, 0xC3
};

BYTE buf_original[13] = { 0x00 };

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    {
        CreateThread(NULL, 0, &preInit, 0, 0, NULL);
    }
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

void start()
{
    while (true)
    {
        lpStartAddr = GetFunAddrByName(GetCurrentProcess(), (char*)"api-ms-win-crt-utility-l1-1-1.dll", (char*)"Java_com_netease_mc_mod_network_common_Library_log");
        if (lpStartAddr != NULL)
            break;
    }

    DWORD oldProtect = 0;
    VirtualProtect((LPVOID)lpStartAddr, sizeof(buf_hook), PAGE_EXECUTE_READWRITE, &oldProtect);
    ReadProcessMemory(GetCurrentProcess(), (LPVOID)lpStartAddr, buf_original, sizeof(buf_hook), NULL);
    VirtualProtect((LPVOID)lpStartAddr, sizeof(buf_hook), oldProtect, &oldProtect);

    asmHook();
}

void asmHook()
{
    DWORD oldProtect = 0;
    DWORD64 methodAddr = (DWORD64)&HookLog;
    memcpy(buf_hook + 2, &methodAddr, sizeof(&methodAddr));
    VirtualProtect((LPVOID)lpStartAddr, sizeof(buf_hook), PAGE_EXECUTE_READWRITE, &oldProtect);
    WriteProcessMemory(GetCurrentProcess(), (LPVOID)lpStartAddr, buf_hook, sizeof(buf_hook), NULL);
    VirtualProtect((LPVOID)lpStartAddr, sizeof(buf_hook), oldProtect, &oldProtect);
}

void asmRecovery()
{
    DWORD oldProtect = 0;
    VirtualProtect((LPVOID)lpStartAddr, sizeof(buf_original), PAGE_EXECUTE_READWRITE, &oldProtect);
    WriteProcessMemory(GetCurrentProcess(), (LPVOID)lpStartAddr, buf_original, sizeof(buf_hook), NULL);
    VirtualProtect((LPVOID)lpStartAddr, sizeof(buf_original), oldProtect, &oldProtect);
}


void JNICALL HookLog(JNIEnv* env, jobject obj, jstring path)
{
    jni_env = env;
    jobject_obj = obj;

    if (MessageBoxA(NULL, ("尝试载入：\n\n" + jstring2str(env, path) + "\n\n是否加入验证列表？\n（提示：非自带文件请选择 <取消>）").c_str(), "ModCheckBypassed By XiaoZhiSoC | QQ群：511732113 | 如果该项目损害到了您的利益，请在QQ群内联系我，我将删除此项目。", MB_OKCANCEL | MB_ICONQUESTION) == IDOK)
    {
        asmRecovery();
        pLog pFun = (pLog)lpStartAddr;
        pFun(env, obj, path);
        asmHook();
    }

    if (!isFrist)
    {
        isFrist = true;
        addJar();
    }
    
    return;
}

void callLog(string path)
{
    asmRecovery();
    pLog pFun = (pLog)lpStartAddr;
    pFun(jni_env, jobject_obj,jni_env->NewStringUTF(path.c_str()));
    asmHook();
}

void addJar()
{
    // MessageBoxA(NULL, "绕过MOD检测开始，请确保相关文件已放入C:\\test", "ModCheckBypassed", NULL);

}

DWORD preInit(LPVOID value)
{
    start();
    return 0;
}


string jstring2str(JNIEnv* env, jstring jstr)
{
    char* rtn = NULL;
    jclass   clsstring = env->FindClass("java/lang/String");
    jstring   strencode = env->NewStringUTF("GB2312");
    jmethodID   mid = env->GetMethodID(clsstring, "getBytes", "(Ljava/lang/String;)[B");
    jbyteArray   barr = (jbyteArray)env->CallObjectMethod(jstr, mid, strencode);
    jsize   alen = env->GetArrayLength(barr);
    jbyte* ba = env->GetByteArrayElements(barr, JNI_FALSE);
    if (alen > 0)
    {
        rtn = (char*)malloc(alen + 1);
        memcpy(rtn, ba, alen);
        rtn[alen] = 0;
    }
    env->ReleaseByteArrayElements(barr, ba, 0);
    std::string stemp(rtn);
    free(rtn);
    return stemp;
}

UINT64 GetFunAddrByName(HANDLE hProcess, char* ModName, char* FunName)
{
    HANDLE hMod;
    PVOID BaseAddress = NULL;
    IMAGE_DOS_HEADER dosheader;
    IMAGE_OPTIONAL_HEADER64 opthdr; //IMAGE_OPTIONAL_HEADER64
    IMAGE_EXPORT_DIRECTORY exports;
    USHORT index = 0;
    ULONG addr, i;
    char pFuncName[100] = { 0 };
    PULONG pAddressOfFunctions;
    PULONG pAddressOfNames;
    PUSHORT pAddressOfNameOrdinals;

    //获取模块基址
    BaseAddress = GetProcessMoudleBase(hProcess, ModName);
    if (!BaseAddress) return 0;

    //获取PE头
    hMod = BaseAddress;
    ReadProcessMemory(hProcess, hMod, &dosheader, sizeof(IMAGE_DOS_HEADER), 0);
    ReadProcessMemory(hProcess, (BYTE*)hMod + dosheader.e_lfanew + 24, &opthdr, sizeof(IMAGE_OPTIONAL_HEADER), 0);
    //ReadProcessMemory(hProcess, (BYTE*)hMod + dosheader.e_lfanew + 24, &opthdr, sizeof(IMAGE_OPTIONAL_HEADER64), 0);

    //查找导出表 
    ReadProcessMemory(hProcess, ((BYTE*)hMod + opthdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress), &exports, sizeof(IMAGE_EXPORT_DIRECTORY), 0);

    pAddressOfFunctions = (ULONG*)((BYTE*)hMod + exports.AddressOfFunctions);
    pAddressOfNames = (ULONG*)((BYTE*)hMod + exports.AddressOfNames);
    pAddressOfNameOrdinals = (USHORT*)((BYTE*)hMod + exports.AddressOfNameOrdinals);

    //对比函数名 
    for (i = 0; i < exports.NumberOfNames; i++)
    {
        ReadProcessMemory(hProcess, pAddressOfNameOrdinals + i, &index, sizeof(USHORT), 0);
        ReadProcessMemory(hProcess, pAddressOfFunctions + index, &addr, sizeof(ULONG), 0);

        ULONG a = 0;
        ReadProcessMemory(hProcess, pAddressOfNames + i, &a, sizeof(ULONG), 0);
        ReadProcessMemory(hProcess, (BYTE*)hMod + a, pFuncName, 100, 0);
        ReadProcessMemory(hProcess, pAddressOfFunctions + index, &addr, sizeof(ULONG), 0);

        if (!_stricmp(pFuncName, FunName))
        {
            UINT64 funAddr = (UINT64)BaseAddress + addr;
            return funAddr;
        }
    }
    return 0;
}

PVOID GetProcessMoudleBase(HANDLE hProcess, char* moduleName)
{
    // 遍历进程模块,
    HMODULE hModule[100] = { 0 };
    DWORD dwRet = 0;
    BOOL bRet = ::EnumProcessModules(hProcess, (HMODULE*)(hModule), sizeof(hModule), &dwRet);
    if (FALSE == bRet)
    {
        ::CloseHandle(hProcess);
        return NULL;
    }
    char name[50] = { 0 };
    for (int i = 0; i < dwRet; i++)
    {
        GetModuleBaseNameA(hProcess, hModule[i], name, 50);

        if (!_strcmpi(moduleName, name))
        {
            return hModule[i];
        }
    }

    ::CloseHandle(hProcess);
    return NULL;
}



