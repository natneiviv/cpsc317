//
// Created by Vivien Tan on 2020-03-17.
//

#ifndef __PARSE_H__
#define __PARSE_H__

void removeLeadingAndTrailingWhiteSpace(char *input, int length);
int numArgs(char *buffer);
int processUSER(int clientSocket, char *buffer);
void processQUIT(int clientSocket, char *buffer, char* root);
void processTYPE(int clientSocket, char* buffer);
void processMODE(int clientSocket, char* buffer);
void processSTRU(int clientSocket, char* buffer);
void processPASV(int clientSocket, char* buffer);
void closePassiveMode();
void processNLST(int clientSocket, char *buffer);
void processRETR(int clientSocket, char *buffer);
void parseInput(int clientSocket, char *buffer, char* root);
void* getInput(void* args);




#endif