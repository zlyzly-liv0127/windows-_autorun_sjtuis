#ifndef MYTHREAD_3_H
#define MYTHREAD_3_H
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
using namespace  std;
class mythread_3 : public QThread
{
    Q_OBJECT
public:
    mythread_3();
    void DoQuerySvc(const char*);
    void QueryKey(HKEY hKey);
    void TcharToChar(const TCHAR* tchar, char* _char);
    void Wchar_tToString(string& szDst, wchar_t *wchar);
    string string_test(const char* a);

protected:
    virtual void run();
signals:
    void title_3(QString,int);
    void content_3(QString,int);
};

#endif // MYTHREAD_3_H
