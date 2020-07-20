#ifndef MYTHREAD_5_H
#define MYTHREAD_5_H

#include<QThread>
#include<windows.h>
#include<string>
#define MAX_KEY_LENGTH 255
#define MAX_VALUE_NAME 16383
#define MAX_VALUE_DATA 16383
#define INFO_BUFFER_SIZE 32767
using namespace std;
class mythread_5 : public QThread
{
    Q_OBJECT
public:
    mythread_5();
    void QueryKey(HKEY hKey);
    string string_test(const char* a, int);
protected:
    virtual void run();
signals:
    void title_5(QString,int);
    void content_5(QString,int);
};

#endif // MYTHREAD_5_H
