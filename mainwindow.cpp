#include "mainwindow.h"

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
    /* 随机数生成实例化 */
    rdNum = new RandNum();
    /* SM2密钥生成实例化 */
    sm2Key = new Sm2Key();
    /* SM2加解密实例化 */
    sm2Encry = new Sm2Encrypt();
    /* SM3哈希实例化 */
    sm3Hash = new Sm3Hash();
    /* SM2签名验签实例化 */
    sm2SignVerify = new Sm2SignVerify();
    /* SM4加解密实例化 */
    sm4Encry = new Sm4encrypt();
    /* SM2签发证书实例化 */
    sm2Cer = new Sm2Cert();
    /* 左侧功能导航 */
    QList<QString> strListWidgetList;
    strListWidgetList << "首页"
                      << "随机数生成"
                      << "SM2密钥生成"
                      << "SM2加解密"
                      << "SM3哈希"
                      << "SM2签名验签"
                      << "SM4加解密"
                      << "SM2签发证书";
    for (int i = 0; i < 8; i++) {
        /* listWidget 插入项 */
        listWidget->insertItem(i, strListWidgetList[i]);
    }
    /* 子页面插入 */
    stackedWidget->addWidget(tsHome);
    stackedWidget->addWidget(rdNum);
    stackedWidget->addWidget(sm2Key);
    stackedWidget->addWidget(sm2Encry);
    stackedWidget->addWidget(sm3Hash);
    stackedWidget->addWidget(sm2SignVerify);
    stackedWidget->addWidget(sm4Encry);
    stackedWidget->addWidget(sm2Cer);
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
