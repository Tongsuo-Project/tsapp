#include "mainwindow.h"
#include <openssl/rand.h>
MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
{
    /* 主界面设置 */
    this->setGeometry(480, 200, 800, 480);

    this->setWindowIcon(QIcon(":/images/TongSuoIcon.png"));

    this->setWindowTitle(QString("TongSuo"));

    /* widget 小部件实例化 */
    widget = new QWidget(this);

    /* 设置居中 */
    this->setCentralWidget(widget);

    /* 垂直布局实例化 */
    hBoxLayout = new QHBoxLayout();

    /* 堆栈部件实例化 */
    stackedWidget = new QStackedWidget();

    /* 列表实例化 */
    listWidget = new QListWidget();

    /* 首页实例化 */
    tsHome = new Home();

    /* 功能1随机数生成实例化 */
    rdNum = new RandNum();

    /* 左侧功能导航 */
    QList<QString> strListWidgetList;
    strListWidgetList << "首页"
                      << "随机数生成";

    for (int i = 0; i < 2; i++) {
        /* listWidget 插入项 */
        listWidget->insertItem(i, strListWidgetList[i]);
    }

    /* 子页面插入 */
    stackedWidget->addWidget(tsHome);

    stackedWidget->addWidget(rdNum);

    /* 设置列表的最大宽度 */
    listWidget->setMaximumWidth(200);

    /* 添加到水平布局 */
    hBoxLayout->addWidget(listWidget);
    hBoxLayout->addWidget(stackedWidget);

    /* 将 widget 的布局设置成 hboxLayout */
    widget->setLayout(hBoxLayout);

    /* 利用 listWidget 的信号函数 currentRowChanged()与槽函数 setCurrentIndex()进行信号与槽连接*/
    connect(listWidget, SIGNAL(currentRowChanged(int)), stackedWidget, SLOT(setCurrentIndex(int)));
}

MainWindow::~MainWindow() {}
