#pragma once

int hostGetNumber(int uid0, int uid1, int idx);
void hostSetNumber(int uid0, int uid1, int idx, int val);
void hostLockNumber(int uid0, int uid1, int idx);
void hostPrint(const char *text);
void hostPrintNum(int num);

void hostError(const char *text);
void hostComplete();

void boundsCheck(int top, int required);

void processRequest(char *text);