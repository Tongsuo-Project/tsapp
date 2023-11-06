#include "tlcpclient.h"
#include "ui_tlcpclient.h"
static SSL *ssl;
TLCPclient::TLCPclient(QWidget *parent)
    : QWidget(parent)
    , ui(new Ui::TLCPclient)
{
    ui->setupUi(this);
    ui->pushButtonSend->setEnabled(false);
}

TLCPclient::~TLCPclient()
{
    delete ui;
}

void TLCPclient::on_pushButtonConnect_clicked()
{
    if (ui->pushButtonConnect->text() == "连接服务器") {
        //载入SSL相关信息
        SSL_library_init();
        SSL_load_error_strings();
        OpenSSL_add_all_algorithms();
        //获取域名端口
        QString addrQstr = this->ui->lineEditAddr->text();
        QString portQstr = this->ui->lineEditPort->text();
        // 创建一个 QSslSocket对象设置地址并连接
        QTcpSocket socket;
        socket.connectToHost(addrQstr, portQstr.toInt());
        if (!socket.waitForConnected()) {
            QMessageBox::warning(NULL,
                                 "connect failed",
                                 QString("TCP connection to server failed"),
                                 QMessageBox::Ok,
                                 QMessageBox::Ok);
        }

        //TCP已连接,准备SSL连接
        const SSL_METHOD *method = NTLS_client_method();
        std::shared_ptr<SSL_CTX> ssl_ctx(SSL_CTX_new(method), SSL_CTX_free);
        SSL_CTX_enable_ntls(ssl_ctx.get());
        SSL_CTX_set_verify(ssl_ctx.get(), SSL_VERIFY_NONE, NULL);
        ssl = SSL_new(ssl_ctx.get());
        SSL_set_fd(ssl, socket.socketDescriptor());
        if (SSL_connect(ssl) == 1) {
            //SSL连接成功
            ui->pushButtonConnect->setText("断开服务器");
            QMessageBox::information(NULL,
                                     "connect success",
                                     QString("TLCP connection to server successful"),
                                     QMessageBox::Ok,
                                     QMessageBox::Ok);

            ui->pushButtonSend->setEnabled(true);
        } else {
            //SSL连接失败
            SSL_shutdown(ssl);
            SSL_free(ssl);
            QMessageBox::warning(NULL,
                                 "connect failed",
                                 QString("SSL connection to server failed"),
                                 QMessageBox::Ok,
                                 QMessageBox::Ok);
            return;
        }
    } else {
        ui->pushButtonConnect->setText("连接服务器");
        ui->pushButtonSend->setEnabled(false);
        if (ssl != NULL) {
            SSL_shutdown(ssl);
            SSL_free(ssl);
        }
        QMessageBox::information(NULL,
                                 "connect closed",
                                 QString("client closed connection"),
                                 QMessageBox::Ok,
                                 QMessageBox::Ok);
    }
}

void TLCPclient::on_pushButtonSend_clicked()
{
    SSL_set_msg_callback(ssl, trace_cb);
    //获取发送内容
    QString inputQstr = this->ui->plainTextEditInput->toPlainText();
    int ret = SSL_write(ssl, inputQstr.toStdString().c_str(), inputQstr.size());
    if (ret < 0) {
        //发送失败
        getError();
        return;
    }
    SSL_set_connect_state(ssl);
    char rxbuf[256] = {0};
    int rxlen = SSL_read(ssl, rxbuf, 256);
    if (rxlen < 0) {
        int err = SSL_get_error(ssl, rxlen);
        while (err == 2) {
            rxlen = SSL_read(ssl, rxbuf, 256);
            err = SSL_get_error(ssl, rxlen);
        }
        getError();
    } else {
        //输出到反馈栏
        this->ui->textBrowserOutput->setText(QString::asprintf("%s", rxbuf));
    }
}

void TLCPclient::trace_cb(
    int write_p, int version, int content_type, const void *buf, size_t msglen, SSL *ssl, void *arg)
{
    std::shared_ptr<BIO> bio(BIO_new(BIO_s_mem()), BIO_free);
    arg = bio.get();
    SSL_trace(write_p, version, content_type, buf, msglen, ssl, arg);
    int len = BIO_pending((BIO *) arg);
    char argbuf[1024] = {};
    BIO_read((BIO *) arg, argbuf, len);
}
