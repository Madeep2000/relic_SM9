#include <stdio.h>  
#include <stdlib.h>  
#include <string.h>  
#include <sys/socket.h>  
#include <arpa/inet.h>  
#include <unistd.h>

#define PORT 8080  
#define MAX_INPUT_LENGTH 1024

int main() {  
    int server_fd, client_fd, read_size;  
    struct sockaddr_in server_addr, client_addr;  
    char input[MAX_INPUT_LENGTH] = {0};  
    char response[MAX_INPUT_LENGTH] = {0};  
    char *hostname = "localhost";  // 主机名

    // 创建套接字  
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {  
        perror("socket failed");  
        exit(EXIT_FAILURE);  
    }

    // 准备服务器地址  
    server_addr.sin_family = AF_INET;  
    server_addr.sin_addr.s_addr = INADDR_ANY;  
    server_addr.sin_port = htons(PORT);

    // 绑定套接字到地址  
    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {  
        perror("bind failed");  
        exit(EXIT_FAILURE);  
    }

    // 监听套接字  
    if (listen(server_fd, 3) < 0) {  
        perror("listen failed");  
        exit(EXIT_FAILURE);  
    }

    // 等待客户端连接  
    printf("Waiting for incoming connections...\n");  
    while (1) {  
        client_fd = accept(server_fd, (struct sockaddr *)&client_addr, (socklen_t *)&sizeof(client_addr));  
        if (client_fd < 0) {  
            perror("accept failed");  
            exit(EXIT_FAILURE);  
        }

        // 输出客户端连接信息  
        printf("Connection from %s:%d\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));

        // 读取客户端输入并发送响应  
        read_size = read(client_fd, input, MAX_INPUT_LENGTH);  
        if (read_size < 0) {  
            perror("read failed");  
            exit(EXIT_FAILURE);  
        }  
        strcpy(response, input);  
        send(client_fd, response, strlen(response), 0);  
    }

    return 0;  
}

