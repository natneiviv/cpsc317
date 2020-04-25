//
// Created by Vivien Tan on 2020-03-17.
// parse.c contains the functional aspect of parsing the commands the client sends.
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <pthread.h>
#include <ctype.h>
#include <ifaddrs.h>

#include "dir.h"
#include "cwd.h"

#define BUF_SIZE 1024

int loggedIn = 0;
int passiveMode = 0;
int passiveSocket = 0;
int initPassiveSocket = 0;
int msg = 0;

/* function adapted from: https://stackoverflow.com/a/3975465 */
void removeLeadingAndTrailingWhiteSpace(char *input, int length) {
    int index = 0;
    /* look for first index w/ non-whitespace character */
    while (input[index] == ' ' || input[index] == '\t') {
        index++;
    }
    int endOfString = 0;
    /* shift left */
    for (int i = 0; input[i + index] != '\r'; i++) {
        input[i] = input[i + index];
        endOfString = i;
    }
    input[endOfString + 1] = '\0'; // an extra +1 to account for the \r?
    int end = length - index - 2; /* -2 because 0-index & must account for the null terminator */
    /* look for first index w/ non-whitespace character from the end of the char array */
    while (input[end] == ' ' || input[end] == '\t' || input[end] == '\0') {
        end--;
    }
    input[end + 1] = '\0';
}

int numArgs(char *buffer) {
    int i = 1;
    int args = 1;
    if (buffer[0] == '\0' || buffer[0] == '\r'|| buffer[0] == '\n') return 0;
    while (i < strlen(buffer)) {
        if (buffer[i] ==' ' || buffer[i] =='\t'){
            args++;
        }
        i++;
    }
    return args;
}

/*
 * 'logs' the user in
 *  returns 1 if user is valid (cs317 only), 0 o/w
 */
int processUSER(int clientSocket, char *buffer) {
    if (loggedIn) { /* already logged in, ignore */
        msg = snprintf(buffer, BUF_SIZE, "530 Already logged in.\r\n");
        write(clientSocket, buffer, msg);
        return loggedIn;
    } else {
        if (numArgs(buffer) != 1) {
            msg = snprintf(buffer, BUF_SIZE, "501 Incorrect number of arguments.\r\n");
            loggedIn = 0;
        } else if (!strncasecmp(buffer, "cs317\r", 6) || !strncasecmp(buffer, "cs317\0", 6)) {
            printf("%s%s\n", "USER ", buffer);  /* prints on the server side */
            msg = snprintf(buffer, BUF_SIZE, "230 Login successful.\r\n");
            loggedIn = 1;
        } else  {
            printf("%s%s\n", "USER ", buffer);
            msg = snprintf(buffer, BUF_SIZE, "530 Not logged in.\r\n");
            loggedIn = 0;
        }
    }
    write(clientSocket, buffer, msg);
    return loggedIn;
}

void processQUIT(int clientSocket, char *buffer, char* root) {
    if (numArgs(buffer) == 0) {
        printf("QUIT\n");
        msg = snprintf(buffer, BUF_SIZE, "221 Goodbye.\r\n");
        write(clientSocket, buffer, msg);
        bzero(buffer, BUF_SIZE);
        loggedIn = 0;
        passiveMode = 0;
        chdir(root);
        close(clientSocket);
    }  else {
        msg = snprintf(buffer, BUF_SIZE, "501 Incorrect number of arguments.\r\n");
        write(clientSocket, buffer, msg);
    }
}

void processTYPE(int clientSocket, char* buffer) {
    printf("%s%s\n", "TYPE ", buffer);

    if (numArgs(buffer) != 1) {
        msg = snprintf(buffer, BUF_SIZE, "501 Incorrect number of arguments.\r\n");
    } else if (!strcasecmp(buffer, "A\0")) {
        msg = snprintf(buffer, BUF_SIZE, "200 Switching to ASCII mode.\r\n");
    } else if (!strcasecmp(buffer, "I\0")) {
        msg = snprintf(buffer, BUF_SIZE, "200 Switching to Binary mode.\r\n");
    } else { /* arg given was not a single char, or other TYPES */
        msg = snprintf(buffer, BUF_SIZE, "504 Bad TYPE command.\r\n");
    }
    write(clientSocket, buffer, msg);

}

void processMODE(int clientSocket, char* buffer) {
    printf("%s%s\n", "MODE ", buffer);

    if (numArgs(buffer) != 1) {
        msg = snprintf(buffer, BUF_SIZE, "501 Incorrect number of arguments.\r\n");
    } else if (!strcasecmp(buffer, "S\0")) {
        msg = snprintf(buffer, BUF_SIZE, "200 Mode set to S.\r\n");
    }  else { /* arg given was not a single char, or other MODES */
        msg = snprintf(buffer, BUF_SIZE, "504 Bad MODE command.\r\n");
    }
    write(clientSocket, buffer, msg);
}

void processSTRU(int clientSocket, char* buffer) {
    printf("%s%s\n", "STRU ", buffer);

    if (numArgs(buffer) != 1) {
        msg = snprintf(buffer, BUF_SIZE, "501 Incorrect number of arguments.\r\n");
    } else if (!strcasecmp(buffer, "F\0")) {
        msg = snprintf(buffer, BUF_SIZE, "200 Structure set to F.\r\n");
    } else { /* arg given was not a single char, other modes provided */
        msg = snprintf(buffer, BUF_SIZE, "504 Bad STRU command.\r\n");
    }
    write(clientSocket, buffer, msg);
}

void processPASV(int clientSocket, char* buffer) {
    int pasvServerSocket = socket(PF_INET, SOCK_STREAM, 0);
    initPassiveSocket = pasvServerSocket;
    struct sockaddr_in address;
    bzero(&address, sizeof(struct sockaddr_in));
    address.sin_family = AF_INET;
    address.sin_port = 0;
    address.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(pasvServerSocket, (const struct sockaddr*) &address, sizeof(struct sockaddr_in)) != 0){
        msg = snprintf(buffer, BUF_SIZE, "425 Can't open data connection.\r\n");
        write(clientSocket, buffer, msg);
        perror("Failed to bind the passive server socket.");
        exit(EXIT_FAILURE);
    }
    struct sockaddr_in psAddress;
    unsigned int psAddressLength = sizeof(psAddress);
    getsockname(pasvServerSocket, (struct sockaddr *) &psAddress, &psAddressLength);
    int pasvPort = (int) ntohs(psAddress.sin_port);

    struct ifaddrs *host;
    getifaddrs(&host);
    char* ipAddress;

    /* retrieving the IP addresses for interfaces adapted from:
     * https://stackoverflow.com/a/4139893
     */
    while (host != NULL){
        if (host->ifa_addr && host->ifa_addr->sa_family == AF_INET) {
            struct sockaddr_in *sock;
            sock = (struct sockaddr_in *) host->ifa_addr;
            char* addr = inet_ntoa(sock->sin_addr);
            if (strcmp(host->ifa_name, "lo") != 0) { /* filter out loopback address */
                ipAddress = inet_ntoa(sock->sin_addr); /* just pick the first one */
                break;
            }
        }
        host = host->ifa_next;
    }

    if (ipAddress != NULL) {
        /* retrieve h1, h2, h3, h4 from the IP address */
        char *ip[BUF_SIZE];
        bzero(ip, BUF_SIZE);
        char* token = strtok(ipAddress, ".");
        int i = 0;
        while (token != NULL){
            ip[i] = strdup(token);
            i++;
            token = strtok(NULL, ".");
        }

        int p1 = pasvPort/256;
        int p2 = pasvPort-(p1*256);
        bzero(buffer, BUF_SIZE);
        msg = snprintf(buffer, BUF_SIZE, "227 Entering Passive Mode (%s,%s,%s,%s,%d,%d).\n", ip[0], ip[1], ip[2], ip[3], p1, p2);
        write(clientSocket, buffer, msg);

        if (listen(pasvServerSocket, 1) != 0) {
            msg = snprintf(buffer, BUF_SIZE, "425 Can't open data connection.\r\n");
            write(clientSocket, buffer, msg);
            perror("Failed to listen for passive connections.");
            exit(EXIT_FAILURE);
        }

        struct sockaddr_in psa;
        socklen_t psaLength = sizeof(psa);
        passiveSocket = accept(pasvServerSocket, (struct sockaddr *) &psa, &psaLength);
        if (passiveSocket < 0) {
            msg = snprintf(buffer, BUF_SIZE, "425 Can't open data connection.\r\n");
            write(clientSocket, buffer, msg);
            perror("Failed to accept passive socket.");
        } else {
            passiveMode = 1;
            printf("%s\n", "PASV");
        }
    } else {
        msg = snprintf(buffer, BUF_SIZE, "425 Can't open data connection.\r\n");
        write(clientSocket, buffer, msg);
    }
}

void closePassiveMode() {
    passiveMode = 0;
    close(passiveSocket);
    close(initPassiveSocket);
}

void processNLST(int clientSocket, char *buffer) {
    char currDir[BUF_SIZE];
    bzero(currDir, BUF_SIZE);
    if (numArgs(buffer) != 0) {
        msg = snprintf(buffer, BUF_SIZE, "501 Incorrect number of arguments.\r\n");
        write(clientSocket, buffer, msg);
    } else if (!passiveMode) {
        msg = snprintf(buffer, BUF_SIZE, "425 Can't open data connection. Use PASV first.\r\n");
        write(clientSocket, buffer, msg);
    } else {
        msg = snprintf(buffer, BUF_SIZE, "150 Here comes the directory listing.\r\n");
        write(clientSocket, buffer, msg);
        getcwd(currDir, BUF_SIZE);
        if (listFiles(passiveSocket, currDir) < 0) {
            msg = snprintf(buffer, BUF_SIZE, "421 Directory send failed. Closing data connection.\r\n");
        } else {
            printf("%s\n", "NLST");
            msg = snprintf(buffer, BUF_SIZE, "226 Directory send OK. Closing data connection.\r\n");
        }
        write(clientSocket, buffer, msg);
        closePassiveMode();
    }
}

void processRETR(int clientSocket, char* buffer) {
    int fd;
    FILE *file;

    printf("%s%s\n", "RETR ", buffer);
    if (numArgs(buffer) != 1) {
        msg = snprintf(buffer, BUF_SIZE, "501 Incorrect number of arguments.\r\n");
        write(clientSocket, buffer, msg);
    } else if (!passiveMode) {
        msg = snprintf(buffer, BUF_SIZE, "425 Can't open data connection. Use PASV first.\r\n");
        write(clientSocket, buffer, msg);
    } else if (access(buffer, F_OK) == -1) { /* file does not exist */
        msg = snprintf(buffer, BUF_SIZE, "550 Requested action not taken. File unavailable.\r\n");
        write(clientSocket, buffer, msg);
    } else { /* file exists */
        file = fopen(buffer, "r");
        fseek(file, 0L, SEEK_END);
        int size = ftell(file);
        rewind(file);
        msg = snprintf(buffer, BUF_SIZE, "150 Opening data connection.\r\n");
        write(clientSocket, buffer, msg);
        char fileToSend[size];
        fread(fileToSend, 1, size, file);
        write(passiveSocket, fileToSend, size);
        fclose(file);
        closePassiveMode();
        msg = snprintf(buffer, BUF_SIZE, "226 File send OK. Closing data connection.\r\n");
        write(clientSocket, buffer, msg);
    }
}

void parseInput(int clientSocket, char *buffer, char* root) {
    if (!strncasecmp(buffer, "USER", 4)) {
        loggedIn = processUSER(clientSocket, buffer + 5);
    } else if (!loggedIn) {     /* must be logged in before the following commands can be run */
        int msg = snprintf(buffer, BUF_SIZE, "530 Please login with USER.\r\n");
        write(clientSocket, buffer, msg);
    } else if (!strncasecmp(buffer, "CDUP", 4)) {
        processCDUP(clientSocket, buffer + 5, root);
    } else if (!strncasecmp(buffer, "CWD", 3)) {
        processCWD(clientSocket, buffer + 4, root);
    } else if (!strncasecmp(buffer, "TYPE", 4)) {
        processTYPE(clientSocket, buffer + 5);
    } else if (!strncasecmp(buffer, "MODE", 4)) {
        processMODE(clientSocket, buffer + 5);
    } else if (!strncasecmp(buffer, "STRU", 4)) {
        processSTRU(clientSocket, buffer + 5);
    } else if (!strncasecmp(buffer, "RETR", 4)) {
        processRETR(clientSocket, buffer + 5);
    } else if (!strncasecmp(buffer, "PASV", 4)) {
        processPASV(clientSocket, buffer + 5);
    } else if (!strncasecmp(buffer, "NLST", 4)) {
        processNLST(clientSocket, buffer + 5);
    } else { /* default */
        int msg = snprintf(buffer, BUF_SIZE, "500 Unknown command.\r\n");
        write(clientSocket, buffer, msg);
    }
}

void *getInput(void *args) {
    int clientSocket = *(int *) args;
    // Interact with the client
    char buffer[BUF_SIZE];
    bzero(buffer, BUF_SIZE);
    /* get the directory in which the server is currently running */
    char root[BUF_SIZE];
    bzero(root, BUF_SIZE);
    getcwd(root, BUF_SIZE);

    msg = snprintf(buffer, BUF_SIZE, "220 Connected to server.\r\n");
    write(clientSocket, buffer, msg);

    while (1) {
        bzero(buffer, BUF_SIZE);
        // Receive the client message
        ssize_t length = read(clientSocket, buffer, BUF_SIZE);
        if (!strncasecmp(buffer, "QUIT", 4)) {
            processQUIT(clientSocket, buffer + 5, root);
        }
        if (length < 0) {
            perror("Failed to read from the socket");
            break;
        } else if (length == 0) {
            printf("EOF\n");
            loggedIn = 0;
            break;
        }
        removeLeadingAndTrailingWhiteSpace(buffer, length);
        parseInput(clientSocket, buffer, root);
    }

    return NULL;
}