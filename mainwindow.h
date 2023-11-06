#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include "home.h"
#include "randnum.h"
#include "sm2cert.h"
#include "sm2encrypt.h"
#include "sm2key.h"
#include "sm2signverify.h"
#include "sm3hash.h"
#include "sm4encrypt.h"
#include "tlcpclient.h"
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
    /* 随机数生成界面 */
    RandNum *rdNum;
    /* sm2密钥生成*/
    Sm2Key *sm2Key;
    /* sm2加密界面*/
    Sm2Encrypt *sm2Encry;
    /* sm3哈希界面 */
    Sm3Hash *sm3Hash;
    /* sm2签名验签界面 */
    Sm2SignVerify *sm2SignVerify;
    /* sm4加解密界面 */
    Sm4encrypt *sm4Encry;
    /* sm2签发证书 */
    Sm2Cert *sm2Cer;
    /* TLCP客户端界面 */
    TLCPclient *tlcpClient;
};
#endif // MAINWINDOW_H
