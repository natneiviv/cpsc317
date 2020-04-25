//
// Created by Vivien Tan on 2020-03-19.
// cwd.c contains code pertaining to changing the working directory. CDUP is included
// in this as it is related to changing the working directory (to its parent).
//
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <ctype.h>

#include "cwd.h"
#include "parse.h"

#define BUF_SIZE 1024

void processCDUP(int clientSocket, char* buffer, char* root) {
    int ret;
    char currDir[BUF_SIZE];
    bzero(currDir, BUF_SIZE);
    getcwd(currDir, BUF_SIZE);
    if (!strcasecmp(currDir, root)) { /* cwd == root */
        ret = snprintf(buffer, BUF_SIZE, "550 Cannot change working directory.\r\n");
    } else { /* cwd != root */
        if (chdir("..") < 0) {
            ret = snprintf(buffer, BUF_SIZE, "550 Cannot change working directory.\r\n");
        } else {
            ret = snprintf(buffer, BUF_SIZE, "250 Directory successfully changed.\n");
            printf("%s\n", "CDUP");
        }
    }
    write(clientSocket, buffer, ret);
}

/* deals with the case when client gives a path starting w/ '/' */
void absolutePath(int clientSocket, char* path, char* root) {
    char fullPath[BUF_SIZE];
    bzero(fullPath, BUF_SIZE);
    char buffer[BUF_SIZE];
    bzero(buffer, BUF_SIZE);
    strcpy(fullPath, root);
    int ret;
    if (!strcmp(path, "/\0") || !strcmp(path, "/\r")) { // wants to change to just the '/', should be root of ftp server
        chdir(root);
        ret = snprintf(buffer, BUF_SIZE, "250 Directory successfully changed.\n");
    } else  { // gives absolute path
        strcat(fullPath, path);
        if (chdir(fullPath) < 0) {
            ret = snprintf(buffer, BUF_SIZE, "550 Cannot change working directory.\r\n");
        } else {
            printf("%s%s\n", "CWD ", path);
            ret = snprintf(buffer, BUF_SIZE, "250 Directory successfully changed.\n");
        }
    }
    write(clientSocket, buffer, ret);
}


void processCWD(int clientSocket, char* buffer, char* root) {
    int ret;
    if (strstr(buffer, "./") != NULL || strstr(buffer, "~") != NULL || strstr(buffer, "../") != NULL) {
        // For security reasons you are not accept any CWD command that starts with ./ or ../ or contains ../ in it.
        ret = snprintf(buffer, BUF_SIZE, "550 Cannot change working directory.\r\n");
        write(clientSocket, buffer, ret);
    } else if (!strcmp(buffer, "..\0") || !strcmp(buffer, ".\0")) {
        ret = snprintf(buffer, BUF_SIZE, "550 Cannot change working directory.\r\n");
        write(clientSocket, buffer, ret);
    } else if (!strncmp(buffer, "/", 1)) { /* path begins with a '/' */
        absolutePath(clientSocket, buffer, root);
    } else { /* relative path */
        if (chdir(buffer) < 0) {
            ret = snprintf(buffer, BUF_SIZE, "550 Cannot change working directory.\r\n");
        } else  {
            printf("%s%s\n", "CWD ", buffer);
            ret = snprintf(buffer, BUF_SIZE, "250 Directory successfully changed.\r\n");
        }
        write(clientSocket, buffer, ret);
    }
}