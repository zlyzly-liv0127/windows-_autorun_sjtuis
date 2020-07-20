#ifndef MYTHREAD_H
#define MYTHREAD_H

#include<QThread>
#include<QObject>
#include<windows.h>
#include<vector>
#include<string>
#define MAX_KEY_LENGTH 255
#define MAX_VALUE_NAME 16383
#define MAX_VALUE_DATA 16383
using namespace std;
class mythread : public QThread
{
    Q_OBJECT
public:
    mythread();
    void QueryKey(HKEY key);
    void find_file(const char* mainDir, vector<string>& files);
    void TcharToChar(const TCHAR* tchar, char* _char);
    bool GetShellPath(const char* Src, LPWSTR ShellPath);
    string string_test(const char* a, int flag);


signals:
    void title(QString,int);
    void content(QString,int);

protected:
    virtual void run();

private:
    volatile bool isStop;
};

#endif // MYTHREAD_H
