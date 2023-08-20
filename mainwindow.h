#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QStackedWidget>
#include <QHBoxLayout>
#include <QListWidget>
#include "home.h"
#include "randnum.h"
#include "sm2encrypt.h"

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();
private:
    /* widget 小部件 */
    QWidget *widget;
    /* 水平布局 */
    QHBoxLayout *hBoxLayout;
    /* 列表视图 */
    QListWidget *listWidget;
    /* 堆栈窗口部件 */
    QStackedWidget *stackedWidget;
    /* 首页界面 */
    Home *tsHome;
    /* 功能1随机数生成界面 */
    RandNum *rdNum;
    /* 功能2sm2加密界面*/
    Sm2Encrypt *sm2Encry;

};
#endif // MAINWINDOW_H
