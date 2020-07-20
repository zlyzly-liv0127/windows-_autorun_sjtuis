#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QThread>
#include "mythread.h"
#include "mythread_2.h"
#include "mythread_3.h"
#include "mythread_4.h"
#include "mythread_5.h"
#include <comdef.h>
#include <taskschd.h>
#include <QTreeWidget>
QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    //void OnMsgSignal(const QString& tep2);
    void updateTitle(QString content, int type);
    void updateContent(QString content, int type);
    void updateTitle_2(QString content, int type);
    void updateContent_2(QString content, int type);
    void updateTitle_3(QString content, int type);
    void updateContent_3(QString content, int type);
    void updateTitle_4(QString content, int type);
    void updateContent_4(QString content, int type);
    void updateTitle_5(QString content, int type);
    void updateContent_5(QString content, int type);




private:
    Ui::MainWindow *ui;
    mythread* m_thread;
    mythread_2* m_thread_2;
    mythread_3* m_thread_3;
    mythread_4* m_thread_4;
    mythread_5* m_thread_5;
    QTreeWidgetItem* reg_head;
    QTreeWidgetItem* reg_child;
    QTreeWidgetItem* svc_head;
    QTreeWidgetItem* svc_child;
    QTreeWidgetItem* drv_head;
    QTreeWidgetItem* drv_child;
    QTreeWidgetItem* tsk_head;
    QTreeWidgetItem* tsk_child;
    QTreeWidgetItem* dll_head;
    QTreeWidgetItem* dll_child;


};
#endif // MAINWINDOW_H
