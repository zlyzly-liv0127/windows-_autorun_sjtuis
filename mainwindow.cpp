#pragma once
#include <windows.h>
#include <stdio.h>
#include <iostream>
#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QTreeWidget>
#include <QString>
#include <QDebug>
#include <QThread>
#include <io.h>
#include <shlobj.h>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    //thread1 for logon
    m_thread = new mythread();
    //connect(m_thread, SIGNAL(MsgSignal(const QString&)),
                //this, SLOT(OnMsgSignal(const QString&)));//此处connect的第五个参数默认变成Qt::QueuedConnection
    connect(m_thread,SIGNAL(title(QString,int)),this,SLOT(updateTitle(QString,int)));
    connect(m_thread,SIGNAL(content(QString,int)),this,SLOT(updateContent(QString,int)));
    m_thread->start();
    //thread2 for services
    m_thread_2 = new mythread_2();
    connect(m_thread_2,SIGNAL(title_2(QString,int)),this,SLOT(updateTitle_2(QString,int)));
    connect(m_thread_2,SIGNAL(content_2(QString,int)),this,SLOT(updateContent_2(QString,int)));//线程容器
    m_thread_2->start();
    //thread3 for drivers
    m_thread_3 = new mythread_3();
    connect(m_thread_3,SIGNAL(title_3(QString,int)),this,SLOT(updateTitle_3(QString,int)));
    connect(m_thread_3,SIGNAL(content_3(QString,int)),this,SLOT(updateContent_3(QString,int)));//线程容器
    m_thread_3->start();
    //thread4 for scheduled tasks
    m_thread_4 = new mythread_4();
    connect(m_thread_4,SIGNAL(title_4(QString,int)),this,SLOT(updateTitle_4(QString,int)));
    connect(m_thread_4,SIGNAL(content_4(QString,int)),this,SLOT(updateContent_4(QString,int)));//线程容器
    m_thread_4->start();
    //thread5 for knowndlls
    m_thread_5 = new mythread_5();
    connect(m_thread_5,SIGNAL(title_5(QString,int)),this,SLOT(updateTitle_5(QString,int)));
    connect(m_thread_5,SIGNAL(content_5(QString,int)),this,SLOT(updateContent_5(QString,int)));//线程容器
    m_thread_5->start();
}

MainWindow::~MainWindow()
{
    delete ui;
}

//updataTitle
void MainWindow::updateTitle(QString content, int type)
{

    if(type == 0)
    {
        reg_head = new QTreeWidgetItem(ui->treeWidget);
        reg_head->setText(0, content);
    }
}
//type变量对应列号，只在type为0时new出一个TreeWidgetItem
void MainWindow::updateContent(QString content, int type)
{

    if(type == 0){
    reg_child = new QTreeWidgetItem(reg_head);
    reg_child->setText(0, content);
    //reg_child->setText(1, content);
    }
    else if(type == 1)
    {
        //reg_child = new QTreeWidgetItem(reg_head);
        reg_child->setText(1, content);
    }
}

void MainWindow::updateTitle_2(QString content, int type)
{
    if(type == 0)
    {
        svc_head = new QTreeWidgetItem(ui->treeWidget_2);
        svc_head->setText(0, content);
    }
    else if(type == 1)
    {

    }
}

void MainWindow::updateContent_2(QString content, int type)
{

    if(type == 0){
    svc_child = new QTreeWidgetItem(svc_head);
    svc_child->setText(0, content);
    //reg_child->setText(1, content);
    }
    else if(type == 1)
    {
        //reg_child = new QTreeWidgetItem(reg_head);
        svc_child->setText(1, content);
    }
    else if(type == 2)
    {
        svc_child->setText(2, content);
    }
    else if(type == 3)
    {
        svc_child->setText(3, content);
    }
    else if(type == 4)
    {
        svc_child->setText(4, content);
    }
}
void MainWindow::updateTitle_3(QString content, int type)
{
    if(type == 0)
    {
        drv_head = new QTreeWidgetItem(ui->treeWidget_3);
        drv_head->setText(0, content);
    }
    else if(type == 1)
    {

    }
}

void MainWindow::updateContent_3(QString content, int type)
{

    if(type == 0){
    drv_child = new QTreeWidgetItem(drv_head);
    drv_child->setText(0, content);
    //reg_child->setText(1, content);
    }
    else if(type == 1)
    {
        //reg_child = new QTreeWidgetItem(reg_head);
        drv_child->setText(1, content);
    }
    else if(type == 2)
    {
        drv_child->setText(2, content);
    }
    else if(type == 3)
    {
        drv_child->setText(3, content);
    }
}
void MainWindow::updateTitle_4(QString content, int type)
{
    if(type == 0)
    {
        tsk_head = new QTreeWidgetItem(ui->treeWidget_4);
        tsk_head->setText(0, content);
    }
    else if(type == 1)
    {

    }
}

void MainWindow::updateContent_4(QString content, int type)
{

    if(type == 0){
    tsk_child = new QTreeWidgetItem(tsk_head);
    tsk_child->setText(0, content);
    //reg_child->setText(1, content);
    }
    else if(type == 1)
    {
        //reg_child = new QTreeWidgetItem(reg_head);
        tsk_child->setText(1, content);
    }
    else if(type == 2)
    {
        tsk_child->setText(2, content);
    }
}
void MainWindow::updateTitle_5(QString content, int type)
{
    if(type == 0)
    {
        dll_head = new QTreeWidgetItem(ui->treeWidget_5);
        dll_head->setText(0, content);
    }
    else if(type == 1)
    {

    }
}

void MainWindow::updateContent_5(QString content, int type)
{

    if(type == 0){
    dll_child = new QTreeWidgetItem(dll_head);
    dll_child->setText(0, content);
    //reg_child->setText(1, content);
    }
    else if(type == 1)
    {
        //reg_child = new QTreeWidgetItem(reg_head);
        dll_child->setText(1, content);
    }
    else if(type == 2)
    {
        dll_child->setText(2, content);
    }
}
