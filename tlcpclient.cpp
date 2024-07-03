#include "tlcpclient.h"
#include "ui_tlcpclient.h"

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
    SSL_free(ssl);
    ssl = NULL;
    SSL_CTX_free(ctx);
    ctx = NULL;
    socket.close();
}

void TLCPclient::on_pushButtonConnect_clicked()
{
    int ret, err;

    if (ui->pushButtonConnect->text() == "连接服务器") {
        //获取域名端口
        QString addrQstr = this->ui->lineEditAddr->text();
        QString portQstr = this->ui->lineEditPort->text();
        QString cipherList = this->ui->lineEditCiphers->text();
        // 创建一个 QSslSocket对象设置地址并连接

        this->socket.reset();
        this->socket.connectToHost(addrQstr, portQstr.toInt());
        if (!this->socket.waitForConnected()) {
            QMessageBox::warning(NULL,
                                 "connect failed",
                                 QString("TCP连接失败，请确认服务器地址&端口号是否正确"),
                                 QMessageBox::Ok,
                                 QMessageBox::Ok);
            return;
        }

        //TCP已连接,准备SSL连接
        if (this->ctx == NULL) {
            this->ctx = SSL_CTX_new(NTLS_client_method());
            if (this->ctx == NULL) {
                return;
            }

            SSL_CTX_enable_ntls(this->ctx);
            SSL_CTX_set_verify(this->ctx, SSL_VERIFY_NONE, NULL);
        }

        if (SSL_CTX_set_cipher_list(this->ctx, cipherList.toStdString().c_str()) != 1) {
            QMessageBox::warning(NULL,
                                 "set cipher list failed",
                                 QString("设置密码套件失败，请确认套件格式是否正确"),
                                 QMessageBox::Ok,
                                 QMessageBox::Ok);
            return;
        }

        SSL_free(this->ssl);
        this->ssl = SSL_new(this->ctx);
        SSL_set_fd(ssl, this->socket.socketDescriptor());

        if (BIO_socket_nbio(this->socket.socketDescriptor(), 0) != 1) {
            QMessageBox::warning(NULL,
                                 "set blocking failed",
                                 QString("设置阻塞模式失败"),
                                 QMessageBox::Ok,
                                 QMessageBox::Ok);
            return;
        }

        ret = SSL_connect(this->ssl);
        if (ret == 1) {
            //SSL连接成功
            ui->pushButtonConnect->setText("断开服务器");

            this->ui->textBrowserDebug->append(QString("TLCP握手成功\n"));

            ui->pushButtonSend->setEnabled(true);
        } else {
            err = SSL_get_error(this->ssl, ret);

            //SSL连接失败
            SSL_shutdown(this->ssl);
            QMessageBox::warning(NULL,
                                 "connect failed",
                                 QString("TLCP连接失败，err:%1").arg(err),
                                 QMessageBox::Ok,
                                 QMessageBox::Ok);
            return;
        }
    } else {
        ui->pushButtonConnect->setText("连接服务器");
        ui->pushButtonSend->setEnabled(false);
        if (this->ssl != NULL) {
            SSL_shutdown(this->ssl);
        }

        this->ui->textBrowserDebug->append(QString("客户端关闭连接\n"));
    }
}

void TLCPclient::on_pushButtonSend_clicked()
{
    //    SSL_set_msg_callback(ssl, trace_cb);
    //获取发送内容
    QString inputQstr = this->ui->plainTextEditInput->toPlainText();
    int ret = SSL_write(this->ssl, inputQstr.toStdString().c_str(), inputQstr.size());
    if (ret < 0) {
        int err = SSL_get_error(this->ssl, ret);

        if (err == SSL_ERROR_SYSCALL && !socket.isOpen()) {
            QMessageBox::warning(NULL,
                                 "write failed",
                                 QString("TLCP发送数据失败，服务端已经关闭连接"),
                                 QMessageBox::Ok,
                                 QMessageBox::Ok);
            return;
        } else {
            QMessageBox::warning(NULL,
                                 "write failed",
                                 QString("TLCP发送数据失败，err:%1").arg(err),
                                 QMessageBox::Ok,
                                 QMessageBox::Ok);
            //发送失败
            //        getError();
            return;
        }
    } else {
        this->ui->textBrowserDebug->append(QString(">>>:\n") + inputQstr + QString("\n"));
    }

    char rxbuf[16384] = {0};
    ret = SSL_read(this->ssl, rxbuf, sizeof(rxbuf));
    if (ret < 0) {
        int err = SSL_get_error(this->ssl, ret);

        QMessageBox::warning(NULL,
                             "read failed",
                             QString("读失败，err:%1").arg(err),
                             QMessageBox::Ok,
                             QMessageBox::Ok);
        return;
    } else {
        // 输出到接收
        this->ui->textBrowserOutput->setText(QString::asprintf("%s", rxbuf));

        this->ui->textBrowserDebug->append(QString("<<<:\n") + QString::asprintf("%s", rxbuf)
                                           + QString("\n"));
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
