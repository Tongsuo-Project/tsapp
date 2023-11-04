#ifndef TLCPCLIENT_H
#define TLCPCLIENT_H

#include <memory>
#include <openssl/ssl.h>
#include <tserror.h>
#ifdef _WIN32
#include <winsock.h>
#endif // _WIN32
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

private slots:
    void on_pushButtonConnect_clicked();

    void on_pushButtonSend_clicked();

private:
    Ui::TLCPclient *ui;
    static void trace_cb(int write_p,
                         int version,
                         int content_type,
                         const void *buf,
                         size_t msglen,
                         SSL *ssl,
                         void *arg);
};

#endif // TLCPCLIENT_H
