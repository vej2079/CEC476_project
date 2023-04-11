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

#pragma comment(lib, "WS2_32")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

using namespace std;

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

int getHostname()
{
    getComputerName();
    return 0;
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

	//Send message to the server

	char buffer[200] = "Hello World";

	int byteCount = send(clientSocket, buffer, 200, 0);

	if (byteCount > 0) {
		cout << "Message sent... - " << buffer << endl;
	}
	else {
		WSACleanup();
	}

    string ip = getIpAddress();
    int byteCount = send(clientSocket, ip, 200, 0);

    if (byteCount > 0) {
        cout << "Message sent... - " << buffer << endl;
    }
    else {
        WSACleanup();
    }

	//Close the socket
	system("pause");
	WSACleanup();


    //Add these so that they send messages
    getHostname();
    cout << "IP address: " << getIpAddress() << endl;
    cout << "MAC address: " << getMacAddress() << endl;
    cout << "OS: " << getOS() << endl;
    cout << "Currently running processes: " << getOS() << endl;
    vector<wstring> processes = getRunningProcesses();
    for (const auto& process : processes)
    {
        wcout << process << endl;
    }

	return 0;
}