#include <windows.h>
#include <shlwapi.h>
#include <iostream>
#include <fstream>
#include <thread>
#include <string>
#include <map>
#include <ctime>
#include <vector>
#include <sstream>
#include <array>
#include <cstring>
#include <stdint.h>
#include "sha1.h"
#include <cctype>
#include <algorithm>

#define SHA1_BLOCK_SIZE 64
#define SHA1_DIGEST_LENGTH 20
#pragma comment(lib, "shlwapi.lib")

std::string readIni(const std::string& path, const std::string& key) {
    std::ifstream file(path);
    if (!file) return "";
    std::string line;
    while (std::getline(file, line)) {
        auto pos = line.find('=');
        if (pos == std::string::npos) continue;
        std::string k = line.substr(0, pos), v = line.substr(pos + 1);
        if (k == key) return v;
    }
    return "";
}

std::string base32_decode(const std::string& input) {
    const char* alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    std::vector<uint8_t> output;
    int buffer = 0, bitsLeft = 0;
    for (char c : input) {
        if (c == '=' || c == ' ') break;
        const char* p = strchr(alphabet, toupper(c));
        if (!p) continue;
        buffer <<= 5;
        buffer |= (p - alphabet);
        bitsLeft += 5;
        if (bitsLeft >= 8) {
            output.push_back((buffer >> (bitsLeft - 8)) & 0xFF);
            bitsLeft -= 8;
        }
    }
    return std::string(output.begin(), output.end());
}

// SHA1 implementation — public domain (Steve Reid, others)
void sha1(const uint8_t* data, size_t len, uint8_t* out);

void hmac_sha1(const uint8_t* key, size_t key_len, const uint8_t* data, size_t data_len, uint8_t output[20]) {
    const size_t blockSize = 64;
    const size_t hashSize = 20;
    uint8_t k_ipad[blockSize] = { 0 };
    uint8_t k_opad[blockSize] = { 0 };
    uint8_t tk[hashSize] = { 0 };

    if (key_len > blockSize) {
        sha1(key, key_len, tk);
        key = tk;
        key_len = hashSize;
    }

    uint8_t k0[blockSize] = { 0 };
    memcpy(k0, key, key_len);

    for (size_t i = 0; i < blockSize; ++i) {
        k_ipad[i] = k0[i] ^ 0x36;
        k_opad[i] = k0[i] ^ 0x5c;
    }

    std::vector<uint8_t> inner_data;
    inner_data.insert(inner_data.end(), k_ipad, k_ipad + blockSize);
    inner_data.insert(inner_data.end(), data, data + data_len);

    uint8_t inner_hash[hashSize];
    sha1(inner_data.data(), inner_data.size(), inner_hash);

    std::vector<uint8_t> outer_data;
    outer_data.insert(outer_data.end(), k_opad, k_opad + blockSize);
    outer_data.insert(outer_data.end(), inner_hash, inner_hash + hashSize);

    sha1(outer_data.data(), outer_data.size(), output);
}

std::string generate_totp(const std::string& secret_base32) {
    std::string key = base32_decode(secret_base32);
    uint64_t timestep = time(nullptr) / 30;
    uint8_t msg[8];
    for (int i = 7; i >= 0; --i) {
        msg[i] = timestep & 0xFF;
        timestep >>= 8;
    }

    uint8_t hash[20];
    hmac_sha1((uint8_t*)key.data(), key.size(), msg, 8, hash);

    int offset = hash[19] & 0x0F;
    int binary =
        ((hash[offset] & 0x7F) << 24) |
        ((hash[offset + 1] & 0xFF) << 16) |
        ((hash[offset + 2] & 0xFF) << 8) |
        (hash[offset + 3] & 0xFF);

    int code = binary % 1000000;
    char buf[7];
    snprintf(buf, sizeof(buf), "%06d", code);
    return std::string(buf);
}

void simulateKey(WORD vk, bool shift = false) {
    INPUT inputs[4] = {};
    int count = 0;
    if (shift) {
        inputs[count].type = INPUT_KEYBOARD;
        inputs[count].ki.wVk = VK_SHIFT;
        count++;
    }
    inputs[count].type = INPUT_KEYBOARD;
    inputs[count].ki.wVk = vk;
    count++;
    inputs[count].type = INPUT_KEYBOARD;
    inputs[count].ki.wVk = vk;
    inputs[count].ki.dwFlags = KEYEVENTF_KEYUP;
    count++;
    if (shift) {
        inputs[count].type = INPUT_KEYBOARD;
        inputs[count].ki.wVk = VK_SHIFT;
        inputs[count].ki.dwFlags = KEYEVENTF_KEYUP;
        count++;
    }
    SendInput(count, inputs, sizeof(INPUT));
    Sleep(30);
}

void sendText(HWND hwnd, const std::string& text, int delay = 50) {
    for (char c : text) {
        SHORT vk = VkKeyScanA(c);
        if (vk == -1) continue;
        bool shift = (vk & 0x0100) != 0;
        WORD vkCode = vk & 0xFF;
        SetForegroundWindow(hwnd);
        simulateKey(vkCode, shift);
        Sleep(delay);
    }
}

bool isValidIP(const std::string& ip) {
    int parts = 0;
    std::istringstream ss(ip);
    std::string token;
    while (std::getline(ss, token, '.')) {
        if (++parts > 4) return false;
        int val = atoi(token.c_str());
        if (val < 0 || val > 255) return false;
    }
    return parts == 4;
}

void addHostsEntry(const std::string& ip) {
    std::ifstream in("C:\\Windows\\System32\\drivers\\etc\\hosts");
    std::string line;
    while (std::getline(in, line)) {
        if (line.find("wh000.pol.com") != std::string::npos && line.find("#ffxi-autologin") != std::string::npos)
            return; // Entry already exists
    }
    in.close();

    std::ofstream out("C:\\Windows\\System32\\drivers\\etc\\hosts", std::ios::app);
    out << "\n" << ip << " wh000.pol.com #ffxi-autologin\n";
}


void removeHostsEntry() {
    const char* path = "C:\\Windows\\System32\\drivers\\etc\\hosts";
    const char* tmpPath = "C:\\Windows\\System32\\drivers\\etc\\hosts.tmp";

    std::ifstream in(path);
    std::ofstream out(tmpPath);

    std::string line;
    while (std::getline(in, line)) {
        // Trim leading/trailing whitespace
        std::string trimmed = line;
        trimmed.erase(0, trimmed.find_first_not_of(" \t\r\n"));
        trimmed.erase(trimmed.find_last_not_of(" \t\r\n") + 1);

        // Skip blank or matching lines
        if (trimmed.empty() || trimmed.find("#ffxi-autologin") != std::string::npos)
            continue;

        out << line << "\n";
    }

    in.close();
    out.close();

    DeleteFileA(path);
    MoveFileA(tmpPath, path);
}



BOOL CALLBACK EnumWindowsProc(HWND hWnd, LPARAM lParam) {
    wchar_t title[256];
    GetWindowTextW(hWnd, title, sizeof(title) / sizeof(wchar_t));
    if (wcsncmp(title, L"PlayOnline Viewer", 17) == 0) {
        *((HWND*)lParam) = hWnd;
        return FALSE;
    }
    return TRUE;
}

int main() {
    char exePath[MAX_PATH];
    GetModuleFileNameA(NULL, exePath, MAX_PATH);
    PathRemoveFileSpecA(exePath);
    std::string baseDir = exePath;

    std::string ini = baseDir + "\\launcher.ini";
    std::string password, totpSecret, args, proxyIP;
    int delay = 6000;
    int slot = 1;

    std::ifstream test(ini);
    if (!test.good()) {
        std::cout << "No launcher.ini found. Please enter the required information:\n";

        std::string input;

        std::cout << "Delay before input starts (in seconds, default 6): ";
        std::getline(std::cin, input);
        if (!input.empty() && std::all_of(input.begin(), input.end(), ::isdigit)) {
            int val = std::stoi(input);
            if (val >= 1 && val <= 20) delay = val * 1000;
        }

        std::cout << "Password: ";
        std::getline(std::cin, password);

        std::cout << "Slot number (default 1): ";
        std::getline(std::cin, input);
        if (!input.empty() && std::all_of(input.begin(), input.end(), ::isdigit)) {
            int s = std::stoi(input);
            if (s >= 1 && s <= 4) slot = s;
        }

        std::cout << "TOTP Secret (optional): ";
        std::getline(std::cin, totpSecret);

        std::cout << "POL Proxy IP (optional): ";
        std::getline(std::cin, proxyIP);

        std::ofstream out(ini);
        out << "delay=" << delay << "\n";
        out << "password=" << password << "\n";
        out << "totp_secret=" << totpSecret << "\n";
        out << "proxyPOL=" << proxyIP << "\n";
        out << "slot=" << slot << "\n";
        out << "args=" << args << "\n";
        out.close();

    }
    else {
        delay = atoi(readIni(ini, "delay").c_str());
        if (delay <= 0) delay = 6000;
        password = readIni(ini, "password");
        totpSecret = readIni(ini, "totp_secret");
        args = readIni(ini, "args");
        proxyIP = readIni(ini, "proxyPOL");
        slot = atoi(readIni(ini, "slot").c_str());
        if (slot < 1 || slot > 4) slot = 1;
    }


    if (isValidIP(proxyIP)) {
        addHostsEntry(proxyIP);
        if (proxyIP == "127.0.0.1") {
            system("start pol-proxy.exe");
        }
    }

    std::string exe = baseDir + "\\Windower.exe";
    if (GetFileAttributesA(exe.c_str()) == INVALID_FILE_ATTRIBUTES) {
        exe = baseDir + "\\pol.exe";
    }

    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    std::string cmdline = exe + " " + args;

    if (!CreateProcessA(NULL, (LPSTR)cmdline.c_str(), NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        std::cerr << "Failed to launch.\n";
        return 1;
    }

    HWND hwnd = nullptr;
    for (int i = 0; i < 60 && !hwnd; ++i) {
        EnumWindows(EnumWindowsProc, (LPARAM)&hwnd);
        if (!hwnd) Sleep(500);
    }

    if (!hwnd) return 2;

    BlockInput(TRUE);
    Sleep(delay);

    
    DWORD fgThread = GetWindowThreadProcessId(GetForegroundWindow(), NULL);
    AttachThreadInput(GetCurrentThreadId(), fgThread, TRUE);
    SetForegroundWindow(hwnd);
    SetFocus(hwnd);
    AttachThreadInput(GetCurrentThreadId(), fgThread, FALSE);
    Sleep(200);

    if (slot > 1) {
        for (int i = 1; i < slot; ++i) {
            simulateKey(VK_DOWN);
            Sleep(200);
        }
    }

    simulateKey(VK_RETURN);
    Sleep(200);



    simulateKey(VK_RETURN);
    Sleep(300);
    simulateKey(VK_RETURN);
    Sleep(500);
    simulateKey(VK_RETURN);
    Sleep(500);
    // simulateKey(VK_RETURN); Sleep(10000); //steam deck delay

    sendText(hwnd, password, 5);
    Sleep(100);

    simulateKey(VK_RETURN);
    Sleep(500);
    simulateKey(VK_DOWN);
    Sleep(300);


    if (!totpSecret.empty()) {
        simulateKey(VK_RETURN);
        std::string totp = generate_totp(totpSecret);
        sendText(hwnd, totp, 5);
        simulateKey(VK_ESCAPE);
        Sleep(100);
        simulateKey(VK_DOWN);
        Sleep(100);
    }

    simulateKey(VK_RETURN);
    Sleep(50);

    simulateKey(VK_RETURN);
    Sleep(500);

    //std::cout << "Done. Unblocking input.\n";
    BlockInput(FALSE);

    //std::thread([] {
    //    Sleep(30000);
    //    removeHostsEntry();
    //    system("taskkill /f /im pol-proxy.exe >nul 2>&1");
    //    }).detach();

    if (isValidIP(proxyIP)) {
        Sleep(20000);
        removeHostsEntry();
    }

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return 0;
}
