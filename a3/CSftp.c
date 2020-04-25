#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <pthread.h>

#include "dir.h"
#include "usage.h"
#include "parse.h"

/* Implementation adapted from SimpleServer.c, presented in tutorial 9 */
int main(int argc, char *argv[]) {
    // Check the command line arguments
    if (argc != 2) {
      usage(argv[0]);
      return -1;
    }
    int listenSocket = socket(PF_INET, SOCK_STREAM, 0);
    if (listenSocket < 0) {
        perror("Failed to create the socket.");
        exit(EXIT_FAILURE);
    }
    int value = 1;
    if (setsockopt(listenSocket, SOL_SOCKET, SO_REUSEADDR, &value, sizeof(int)) != 0){
        perror("Failed to set the socket option");
        exit(EXIT_FAILURE);
    }
    int portNumber = atoi(argv[1]);
    // Bind the socket to a port
    struct sockaddr_in address;
    bzero(&address, sizeof(struct sockaddr_in));
    address.sin_family = AF_INET;
    address.sin_port = htons(portNumber);
    address.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(listenSocket, (const struct sockaddr*) &address, sizeof(struct sockaddr_in)) != 0){
        perror("Failed to bind the socket");
        exit(EXIT_FAILURE);
    }
    // Set the socket to listen for connections
    if (listen(listenSocket, 4) != 0){
        perror("Failed to listen for connections");
        exit(EXIT_FAILURE);
    }
    printf("%s\n", "Listening for connections.");
    while (1) {
        struct sockaddr_in clientAddr;
        socklen_t clientAddrLength = sizeof(clientAddr);
        int clientSocket = accept(listenSocket, (struct sockaddr *) &clientAddr, &clientAddrLength);
        if (clientSocket < 0) {
            perror("Failed to accept the client connection.\n");
            continue;
        }
        printf("Accepted the client connection from %s:%d.\n", inet_ntoa(clientAddr.sin_addr), ntohs(clientAddr.sin_port));

        // Create a separate thread to interact with the client
        pthread_t thread;

        if (pthread_create(&thread, NULL, getInput, &clientSocket) != 0){
            perror("Failed to create the thread");
            continue;
        }
        // The main thread just waits until the interaction is done
        pthread_join(thread, NULL);

        printf("Interaction thread has finished.\n");
    }
}
