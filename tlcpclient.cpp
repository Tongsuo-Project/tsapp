#ifdef _WIN32
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

        WORD w_req = MAKEWORD(2, 2); //版本号
        WSADATA wsadata;
        WSAStartup(w_req, &wsadata);

        SOCKET client = socket(AF_INET, SOCK_STREAM, 0);
        SOCKADDR_IN client_addr;
        memset(&client_addr, 0, sizeof(client_addr)); //清零
        //获取域名端口
        QString addrQstr = this->ui->lineEditAddr->text();
        QString portQstr = this->ui->lineEditPort->text();
        //设置地址并连接
        client_addr.sin_family = AF_INET;
        client_addr.sin_addr.s_addr = inet_addr(
            addrQstr.toStdString().c_str()); //server端ip地址112.64.122.183 111.205.162.151
        client_addr.sin_port = htons(portQstr.toInt()); //监听端口
        if (::connect(client, (SOCKADDR *) &client_addr, sizeof(SOCKADDR)) == SOCKET_ERROR) {
            QMessageBox::warning(NULL,
                                 "connect failed",
                                 QString("TCP connection to server failed"),
                                 QMessageBox::Ok,
                                 QMessageBox::Ok);
            return;
        }
        //TCP已连接,准备SSL连接
        const SSL_METHOD *method = NTLS_client_method();
        SSL_CTX *ssl_ctx = SSL_CTX_new(method);
        SSL_CTX_enable_ntls(ssl_ctx);
        SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_NONE, NULL);
        ssl = SSL_new(ssl_ctx);
        SSL_set_fd(ssl, client);
        if (SSL_connect(ssl) == 1) {
            //SSL连接成功
            ui->pushButtonConnect->setText("断开服务器");
            QMessageBox::information(NULL,
                                     "connect success",
                                     QString("TLCP connection to server successful"),
                                     QMessageBox::Ok,
                                     QMessageBox::Ok);

            ui->pushButtonSend->setEnabled(true);
            struct timeval tv;
            tv.tv_sec = 10;
            tv.tv_usec = 0;
            setsockopt(client, SOL_SOCKET, SO_SNDTIMEO, (char *) &tv, sizeof(struct timeval));
            setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, (char *) &tv, sizeof(struct timeval));
            SSL_CTX_set_mode(ssl_ctx, SSL_MODE_AUTO_RETRY);
        } else {
            //SSL连接失败
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
    BIO *bio = NULL;
    if (arg == NULL) {
        bio = BIO_new(BIO_s_mem());
        arg = bio;
    }
    SSL_trace(write_p, version, content_type, buf, msglen, ssl, arg);
    int len = BIO_pending((BIO *) arg);
    char argbuf[1024] = {};
    BIO_read((BIO *) arg, argbuf, len);
    BIO_free(bio);
}
#endif
