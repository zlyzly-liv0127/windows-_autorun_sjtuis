#include "mainwindow.h"
//#include <windows.h>
#include <QApplication>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    MainWindow w;
    w.setWindowTitle("MyAutoRun");
    w.show();
    return a.exec();
}
