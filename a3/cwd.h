//
// Created by Vivien Tan on 2020-03-19.
//

#ifndef __CWD_H
#define __CWD_H

void processCDUP(int clientSocket, char* buffer, char* root);
void processCWD(int clientSocket, char* buffer, char* root);
void absolutePath(int clientSocket, char* path, char* root);

#endif
