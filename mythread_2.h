#ifndef MYTHREAD_2_H
#define MYTHREAD_2_H
#include<QThread>
#include<QObject>
#pragma once
#include<windows.h>
#include<stdio.h>
#include<string>
#define MAX_KEY_LENGTH 255
#define MAX_VALUE_NAME 16383
#define MAX_VALUE_DATA 16383
#define INFO_BUFFER_SIZE 32767
using namespace std;

class mythread_2 : public QThread
{
    Q_OBJECT
public:
    mythread_2();
    int DoQuerySvc(const char*);
    void QueryKey(HKEY hKey);
    void TcharToChar(const TCHAR* tchar, char* _char);
    void Wchar_tToString(string& szDst, wchar_t *wchar);
protected:
    virtual void run();
signals:
    void title_2(QString,int);
    void content_2(QString,int);
};

#endif // MYTHREAD_2_H
