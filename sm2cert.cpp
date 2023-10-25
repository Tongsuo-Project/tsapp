#include "sm2cert.h"
#include "ui_sm2cert.h"

Sm2Cert::Sm2Cert(QWidget *parent)
    : QWidget(parent)
    , ui(new Ui::Sm2Cert)
{
    ui->setupUi(this);
}

Sm2Cert::~Sm2Cert()
{
    delete ui;
}
std::shared_ptr<X509> Sm2Cert::genCert(int type,
                                       std::shared_ptr<X509> midCA,
                                       std::shared_ptr<EVP_PKEY> midcaPkey,
                                       QString CNname,
                                       QString days)
{
    /* 生成用户密钥 */
    std::shared_ptr<EVP_PKEY> userKey(EVP_PKEY_Q_keygen(NULL, NULL, "SM2"), EVP_PKEY_free);
    if (userKey.get() == NULL) {
        /* 错误处理 */
        getError();
        exit(0);
    }
    /* 输出用户私钥 */
    std::shared_ptr<BIO> out(BIO_new(BIO_s_mem()), BIO_free);
    PEM_write_bio_PrivateKey(out.get(), userKey.get(), NULL, 0, NULL, NULL, NULL);
    int len = BIO_pending(out.get());
    char buf[1024] = {};
    BIO_read(out.get(), buf, len);
    if (type == 0) {
        this->ui->textBrowserEncryKey->setText(QString(buf));
    } else {
        this->ui->textBrowserSignKey->setText(QString(buf));
    }
    /* 生成CSR */
    std::shared_ptr<X509_REQ> userReq(X509_REQ_new(), X509_REQ_free);
    /* CSR相关设置 */
    X509_REQ_set_pubkey(userReq.get(), userKey.get());

    std::shared_ptr<X509_NAME> userCAname(X509_NAME_new(), X509_NAME_free);
    X509_NAME_add_entry_by_txt(userCAname.get(),
                               "CN",
                               MBSTRING_ASC,
                               (unsigned char *) CNname.toStdString().c_str(),
                               -1,
                               -1,
                               0);
    X509_REQ_set_subject_name(userReq.get(), userCAname.get());

    X509_REQ_set_version(userReq.get(), X509_VERSION_3);
    X509_REQ_sign(userReq.get(), userKey.get(), EVP_sm3());
    X509_REQ_verify(userReq.get(), userKey.get());

    /* 签发证书 */
    std::shared_ptr<X509> userCer(X509_new(), X509_free);
    /* 证书相关设置 */
    std::string str;
    if (type == 0) {
        str = "Key Encipherment, Data Encipherment";
    } else {
        str = "Digital Signature";
    }
    std::shared_ptr<X509_EXTENSION>
        cert_ex(X509V3_EXT_conf_nid(NULL, NULL, NID_key_usage, str.c_str()), X509_EXTENSION_free);
    X509_add_ext(userCer.get(), cert_ex.get(), -1);

    X509_set_version(userCer.get(), X509_VERSION_3);
    X509_set_pubkey(userCer.get(), userKey.get());

    std::shared_ptr<ASN1_INTEGER> aserial(ASN1_INTEGER_new(), ASN1_INTEGER_free);
    ASN1_INTEGER_set(aserial.get(), 0);
    X509_set_serialNumber(userCer.get(), aserial.get());

    X509_set_subject_name(userCer.get(), userCAname.get());

    const X509_NAME *rootCAname = X509_get_subject_name(midCA.get());
    X509_set_issuer_name(userCer.get(), rootCAname);

    time_t curTime = time(NULL);
    std::shared_ptr<ASN1_TIME> rootBeforeTime(ASN1_TIME_new(), ASN1_TIME_free);
    ASN1_TIME_set(rootBeforeTime.get(), curTime);
    X509_set_notBefore(userCer.get(), rootBeforeTime.get());
    std::shared_ptr<ASN1_TIME>
        rootAfterTime(ASN1_TIME_adj(NULL, curTime, 0, days.toInt() * 60 * 60 * 24), ASN1_TIME_free);
    X509_set_notAfter(userCer.get(), rootAfterTime.get());
    /* 使用中间CA私钥签发 */
    X509_sign(userCer.get(), midcaPkey.get(), EVP_sm3());

    return userCer;
}

void Sm2Cert::on_pushButtonGen_clicked()
{
    /* 获取用户输入的通用名称 */
    QString CN = this->ui->lineEditCN->text();
    if (CN.isEmpty()) {
        QMessageBox::warning(NULL,
                             "warning",
                             QString("请输入通用名称！"),
                             QMessageBox::Close,
                             QMessageBox::Close);
        return;
    }
    /* 获取用户输入的有效期 */
    QString days = this->ui->lineEditDays->text();
    if (days.isEmpty()) {
        QMessageBox::warning(NULL,
                             "warning",
                             QString("请输入有效期！"),
                             QMessageBox::Close,
                             QMessageBox::Close);
        return;
    }
    /* 读取中间CA证书 */
    QFile fsubca(":/certs/subca.pem");
    if (!fsubca.open(QIODevice::ReadOnly | QIODevice::Text)) {
        QMessageBox::warning(NULL,
                             "warning",
                             QString("subca.pem打开失败！"),
                             QMessageBox::Close,
                             QMessageBox::Close);
        return;
    }
    QTextStream subcaInput(&fsubca);
    QString subcaQstr = subcaInput.readAll();
    std::shared_ptr<BIO> subcaOut(BIO_new(BIO_s_mem()), BIO_free);
    BIO_write(subcaOut.get(), subcaQstr.toStdString().c_str(), subcaQstr.size());
    std::shared_ptr<X509> subca(PEM_read_bio_X509(subcaOut.get(), NULL, NULL, NULL), X509_free);
    fsubca.close();

    /* 读取中间CA私钥 */
    QFile fpkey(":/certs/subca_pkey.pem");
    if (!fpkey.open(QIODevice::ReadOnly | QIODevice::Text)) {
        QMessageBox::warning(NULL,
                             "warning",
                             QString("subca_pkey.pem打开失败！"),
                             QMessageBox::Close,
                             QMessageBox::Close);
        return;
    }
    QTextStream pkeyInput(&fpkey);
    QString pkeyQstr = pkeyInput.readAll();
    std::shared_ptr<BIO> pkeyOut(BIO_new(BIO_s_mem()), BIO_free);
    BIO_write(pkeyOut.get(), pkeyQstr.toStdString().c_str(), pkeyQstr.size());
    std::shared_ptr<EVP_PKEY> pkey(PEM_read_bio_PrivateKey(pkeyOut.get(), NULL, NULL, NULL),
                                   EVP_PKEY_free);
    fpkey.close();

    /* 生成用户签名证书 */
    std::shared_ptr<X509> userSignCer = this->genCert(1, subca, pkey, CN, days);
    /* 生成用户加密证书 */
    std::shared_ptr<X509> userEncryptCer = this->genCert(0, subca, pkey, CN, days);
    /* 将用户证书以PEM格式输出到输出栏 */
    std::shared_ptr<BIO> outSign(BIO_new(BIO_s_mem()), BIO_free);
    PEM_write_bio_X509(outSign.get(), userSignCer.get());
    int len = BIO_pending(outSign.get());
    char buf[2048] = {};
    BIO_read(outSign.get(), buf, len);
    this->ui->textBrowserSignOutput->setPlainText(QString(buf));
    std::shared_ptr<BIO> outEncrypt(BIO_new(BIO_s_mem()), BIO_free);
    PEM_write_bio_X509(outEncrypt.get(), userEncryptCer.get());
    len = BIO_pending(outEncrypt.get());
    BIO_read(outEncrypt.get(), buf, len);
    this->ui->textBrowserEncryptOutput->setPlainText(QString(buf));
}
