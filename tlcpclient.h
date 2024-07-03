#ifndef TLCPCLIENT_H
#define TLCPCLIENT_H

#include <memory>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <tserror.h>
#include <QTcpSocket>
#include <QWidget>
#pragma comment(lib, "ws2_32.lib")

namespace Ui {
class TLCPclient;
}

class TLCPclient : public QWidget
{
    Q_OBJECT

public:
    explicit TLCPclient(QWidget *parent = nullptr);
    ~TLCPclient();
    static void trace_cb(int write_p,
                         int version,
                         int content_type,
                         const void *buf,
                         size_t msglen,
                         SSL *ssl,
                         void *arg);
private slots:
    void on_pushButtonConnect_clicked();

    void on_pushButtonSend_clicked();

private:
    Ui::TLCPclient *ui;
    QTcpSocket socket;
    SSL_CTX *ctx;
    SSL *ssl;
};

#endif // TLCPCLIENT_H
