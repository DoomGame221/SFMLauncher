#include <windows.h>
#include <iostream>
#include <string>
#include <filesystem>
#include <shlobj.h>
#include <tlhelp32.h>
#include <vector>
#include <fstream>

namespace fs = std::filesystem;

class SFMLauncher {
public:
    static void printHeader() {
        std::cout << "================================================" << std::endl;
        std::cout << "   Source Filmmaker Launcher v2.0" << std::endl;
        std::cout << "================================================" << std::endl;
        std::cout << std::endl;
    }

    // ตรวจสอบว่ากำลังรันด้วยสิทธิ Admin หรือไม่
    static bool isRunningAsAdmin() {
        BOOL isAdmin = FALSE;
        PSID adminGroup = NULL;
        SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;

        if (AllocateAndInitializeSid(&ntAuthority, 2, 
            SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
            0, 0, 0, 0, 0, 0, &adminGroup)) {
            CheckTokenMembership(NULL, adminGroup, &isAdmin);
            FreeSid(adminGroup);
        }

        return isAdmin == TRUE;
    }

    // ขอสิทธิ Admin และรันโปรแกรมใหม่
    static bool requestAdminAndRestart() {
        char exePath[MAX_PATH];
        GetModuleFileNameA(NULL, exePath, MAX_PATH);

        SHELLEXECUTEINFOA sei = { sizeof(sei) };
        sei.lpVerb = "runas";
        sei.lpFile = exePath;
        sei.hwnd = NULL;
        sei.nShow = SW_NORMAL;

        if (!ShellExecuteExA(&sei)) {
            DWORD error = GetLastError();
            if (error == ERROR_CANCELLED) {
                std::cerr << "[X] User cancelled the UAC prompt" << std::endl;
            } else {
                std::cerr << "[X] Failed to request admin privileges. Error: " << error << std::endl;
            }
            return false;
        }

        return true;
    }

    // ค้นหา path ของ SFM
    static std::string findSFMPath() {
        std::vector<std::string> possiblePaths = {
            "C:\\Program Files (x86)\\Steam\\steamapps\\common\\SourceFilmmaker\\game\\sfm.exe",
            "D:\\SteamLibrary\\steamapps\\common\\SourceFilmmaker\\game\\sfm.exe",
            "E:\\Steam\\steamapps\\common\\SourceFilmmaker\\game\\sfm.exe",
            "E:\\SteamLibrary\\steamapps\\common\\SourceFilmmaker\\game\\sfm.exe",
            "F:\\Steam\\steamapps\\common\\SourceFilmmaker\\game\\sfm.exe",
            "F:\\SteamLibrary\\steamapps\\common\\SourceFilmmaker\\game\\sfm.exe"
        };

        for (const auto& path : possiblePaths) {
            if (fs::exists(path)) {
                return path;
            }
        }

        return "";
    }

    // ตรวจสอบการตั้งค่า compatibility mode
    static bool checkCompatibilityMode(const std::string& exePath, std::string& currentFlags) {
        HKEY hKey;
        const char* regPath = "Software\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Layers";
        
        if (RegOpenKeyExA(HKEY_CURRENT_USER, regPath, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            char value[512];
            DWORD valueSize = sizeof(value);
            
            if (RegQueryValueExA(hKey, exePath.c_str(), NULL, NULL, (LPBYTE)value, &valueSize) == ERROR_SUCCESS) {
                currentFlags = std::string(value);
                RegCloseKey(hKey);
                
                // ตรวจสอบว่ามีทั้ง WIN7RTM และ RUNASADMIN
                return (currentFlags.find("WIN7RTM") != std::string::npos &&
                        currentFlags.find("RUNASADMIN") != std::string::npos);
            }
            
            RegCloseKey(hKey);
        }
        
        return false;
    }

    // ตั้งค่า compatibility mode
    static bool setCompatibilityMode(const std::string& exePath) {
        HKEY hKey;
        const char* regPath = "Software\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Layers";
        
        // สร้าง key ถ้ายังไม่มี
        if (RegCreateKeyExA(HKEY_CURRENT_USER, regPath, 0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL) != ERROR_SUCCESS) {
            return false;
        }
        
        const char* flags = "~ WIN7RTM RUNASADMIN";
        LONG result = RegSetValueExA(hKey, exePath.c_str(), 0, REG_SZ, 
                                     (const BYTE*)flags, strlen(flags) + 1);
        
        RegCloseKey(hKey);
        return result == ERROR_SUCCESS;
    }

    // เปิด SFM
    static bool launchSFM(const std::string& exePath) {
        SHELLEXECUTEINFOA sei = { sizeof(sei) };
        sei.fMask = SEE_MASK_NOCLOSEPROCESS;
        sei.lpVerb = "open";
        sei.lpFile = exePath.c_str();
        sei.nShow = SW_NORMAL;

        if (!ShellExecuteExA(&sei)) {
            return false;
        }

        // รอให้ process เริ่มต้น
        if (sei.hProcess) {
            WaitForInputIdle(sei.hProcess, 5000);
            
            DWORD processId = GetProcessId(sei.hProcess);
            if (processId != 0) {
                std::cout << "[OK] SFM launched successfully!" << std::endl;
                std::cout << "     Process ID: " << processId << std::endl;
            }
            
            CloseHandle(sei.hProcess);
        }

        return true;
    }

    // ตรวจสอบว่า SFM process ยังทำงานอยู่หรือไม่
    static bool isSFMRunning() {
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) {
            return false;
        }

        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);

        bool found = false;
        if (Process32First(hSnapshot, &pe32)) {
            do {
                std::string procName = (char*)pe32.szExeFile;
                // แปลงเป็นตัวพิมพ์เล็กเพื่อเปรียบเทียบ
                for (auto& c : procName) c = tolower(c);

                if (procName == "sfm.exe") {
                    found = true;
                    break;
                }
            } while (Process32Next(hSnapshot, &pe32));
        }

        CloseHandle(hSnapshot);
        return found;
    }

    // เปิด Folder
    static void openFolder(const std::string& path) {
        ShellExecuteA(NULL, "explore", path.c_str(), NULL, NULL, SW_SHOW);
    }
};

int main() {
    // ตั้งค่า console เป็น UTF-8
    SetConsoleOutputCP(CP_UTF8);
    
    SFMLauncher::printHeader();

    // ตรวจสอบสิทธิ Admin
    if (!SFMLauncher::isRunningAsAdmin()) {
        std::cout << "[!] Not running as Administrator" << std::endl;
        std::cout << "[*] Requesting Administrator privileges..." << std::endl;
        std::cout << std::endl;
        
        if (SFMLauncher::requestAdminAndRestart()) {
            // ปิดโปรแกรมปัจจุบัน ให้ instance ใหม่ที่มีสิทธิ admin ทำงานต่อ
            return 0;
        } else {
            std::cout << std::endl;
            std::cout << "Press Enter to exit...";
            std::cin.get();
            return 1;
        }
    }

    std::cout << "[OK] Running with Administrator privileges" << std::endl;
    std::cout << std::endl;

    // ค้นหา SFM
    std::cout << "[*] Searching for Source Filmmaker..." << std::endl;
    std::string sfmPath = SFMLauncher::findSFMPath();

    if (sfmPath.empty()) {
        std::cout << "[X] Error: Could not find sfm.exe" << std::endl;
        std::cout << std::endl;
        std::cout << "Searched in:" << std::endl;
        std::cout << "  - C:\\Program Files (x86)\\Steam\\steamapps\\common\\SourceFilmmaker\\game\\sfm.exe" << std::endl;
        std::cout << "  - D:\\SteamLibrary\\steamapps\\common\\SourceFilmmaker\\game\\sfm.exe" << std::endl;
        std::cout << "  - E:\\SteamLibrary\\steamapps\\common\\SourceFilmmaker\\game\\sfm.exe" << std::endl;
        std::cout << "  - F:\\SteamLibrary\\steamapps\\common\\SourceFilmmaker\\game\\sfm.exe" << std::endl;
        std::cout << std::endl;
        std::cout << "Press Enter to exit...";
        std::cin.get();
        return 1;
    }

    std::cout << "[OK] Found SFM at:" << std::endl;
    std::cout << "     " << sfmPath << std::endl;
    std::cout << std::endl;

    // ตรวจสอบ compatibility mode
    std::cout << "[*] Checking compatibility settings..." << std::endl;
    std::string currentFlags;
    bool isConfigured = SFMLauncher::checkCompatibilityMode(sfmPath, currentFlags);

    if (isConfigured) {
        std::cout << "[OK] Compatibility mode already configured correctly!" << std::endl;
        std::cout << "     Settings: " << currentFlags << std::endl;
    } else {
        if (!currentFlags.empty()) {
            std::cout << "[!] Current settings: " << currentFlags << std::endl;
        } else {
            std::cout << "[!] No compatibility settings found" << std::endl;
        }
        
        std::cout << "[*] Applying Windows 7 + Admin compatibility mode..." << std::endl;
        
        if (SFMLauncher::setCompatibilityMode(sfmPath)) {
            std::cout << "[OK] Compatibility settings applied successfully!" << std::endl;
        } else {
            std::cout << "[X] Failed to apply compatibility settings" << std::endl;
        }
    }

    std::cout << std::endl;

    // เปิด SFM
    std::cout << "[*] Launching Source Filmmaker..." << std::endl;
    std::cout << std::endl;
    std::cout << "================================================" << std::endl;
    std::cout << "   Starting SFM..." << std::endl;
    std::cout << "================================================" << std::endl;
    std::cout << std::endl;

    if (SFMLauncher::launchSFM(sfmPath)) {
        std::cout << std::endl;
        std::cout << "================================================" << std::endl;
        std::cout << "   SFM is now running!" << std::endl;
        std::cout << "   Waiting for SFM to fully load..." << std::endl;
        std::cout << "================================================" << std::endl;
        std::cout << std::endl;

        // รอให้ SFM เริ่มต้นเสร็จ
        std::cout << "[*] Checking if SFM is running..." << std::endl;
        
        // รอสูงสุด 10 วินาที
        int attempts = 0;
        bool sfmDetected = false;
        
        while (attempts < 10) {
            Sleep(1000);  // รอ 1 วินาที
            
            if (SFMLauncher::isSFMRunning()) {
                sfmDetected = true;
                std::cout << "[OK] SFM process confirmed running!" << std::endl;
                // อ่าน path จาก path.txt
                std::ifstream pathFile("path.txt");
                std::string sessionsPath;
                if (std::getline(pathFile, sessionsPath)) {
                    std::cout << "[*] Opening sessions folder..." << std::endl;
                    SFMLauncher::openFolder(sessionsPath);
                    
                    // เปิด Work1 folder
                    std::string work1Path = "D:\\My-Coding-Project\\SFM-Animations\\Work1";
                    std::cout << "[*] Opening Work1 folder..." << std::endl;
                    SFMLauncher::openFolder(work1Path);
                }
                break;
            }
            
            attempts++;
            std::cout << "." << std::flush;
        }
        
        std::cout << std::endl;
        
        if (sfmDetected) {
            std::cout << std::endl;
            std::cout << "================================================" << std::endl;
            std::cout << "   SFM started successfully!" << std::endl;
            std::cout << "   Closing launcher in 2 seconds..." << std::endl;
            std::cout << "================================================" << std::endl;
            
            // รอ 2 วินาทีแล้วปิดอัตโนมัติ
            Sleep(2000);
            return 0;
        } else {
            std::cout << "[!] Warning: Could not detect SFM process" << std::endl;
            std::cout << "    SFM might still be loading..." << std::endl;
            std::cout << std::endl;
            std::cout << "Press Enter to exit...";
            std::cin.get();
            return 0;
        }
    } else {
        std::cout << "[X] Failed to launch SFM" << std::endl;
        std::cout << std::endl;
        std::cout << "Press Enter to exit...";
        std::cin.get();
        return 1;
    }

    std::cout << std::endl;
    std::cout << "Press Enter to exit...";
    std::cin.get();

    return 0;
}