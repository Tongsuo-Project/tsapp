#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include "home.h"
#include "randnum.h"
#include <QHBoxLayout>
#include <QListWidget>
#include <QMainWindow>
#include <QStackedWidget>

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
};
#endif // MAINWINDOW_H
