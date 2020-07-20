#ifndef MYTHREAD_4_H
#define MYTHREAD_4_H
#include<QThread>
#include<QObject>
#pragma once
#include<windows.h>
#include<stdio.h>
#include<iostream>
#include<comdef.h>
#include<taskschd.h>
#include<string>
#define INFO_BUFFER_SIZE 32767
#pragma comment(lib, "taskschd.lib")
#pragma comment(lib, "comsupp.lib")

using namespace std;
class mythread_4 : public QThread
{
    Q_OBJECT
public:
    mythread_4();
    //void DoQuerySvc(const char*);
    void walkFoldersFormat(ITaskFolder* rootFolder, HRESULT hr);
    void getTasksFormat(ITaskFolder* rootFolder, HRESULT hr);
    void get_task();
    void wchar2strstring(std::string & szDst,WCHAR * wchart);
    string a;
    string tmp;

protected:
    virtual void run();
signals:
    void title_4(QString,int);
    void content_4(QString,int);
};

#endif // MYTHREAD_4_H
