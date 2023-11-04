#ifndef TLCPCLIENT_H
#define TLCPCLIENT_H
#ifdef _WIN32

#include <memory>
#include <openssl/ssl.h>
#include <tserror.h>
#include <winsock.h>
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

#endif // _WIN32
#endif // TLCPCLIENT_H
