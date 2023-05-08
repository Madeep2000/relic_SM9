#include <stdio.h>    
#include <stdlib.h>    
#include <string.h>    
#include <sys/socket.h>    
#include <arpa/inet.h>    
#include <unistd.h>

#define PORT 8080  

int main() {    
    int sock = socket(AF_INET, SOCK_STREAM, 0);    
    struct sockaddr_in server_addr;    
    memset(&server_addr, 0, sizeof(server_addr));    
    server_addr.sin_family = AF_INET;    
    server_addr.sin_addr.s_addr = INADDR_ANY;    
    server_addr.sin_port = htons(PORT);

    connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr));

    char buffer[1024];    
    while (1) {    
        int size = recv(sock, buffer, sizeof(buffer), 0);    
        if (size <= 0) {    
            break;    
        }    
        printf("%s\n", buffer);    
    }

    close(sock);  
    return 0;  
}
