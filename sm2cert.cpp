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

std::shared_ptr<X509> Sm2Cert::genRootCA()
{
    /* 生成根密钥 */
    std::shared_ptr<EVP_PKEY> rootKey(EVP_PKEY_Q_keygen(NULL, NULL, "SM2"), EVP_PKEY_free);
    if (rootKey.get() == NULL) {
        /* 错误处理 */
        getError();
        exit(0);
    }
    /* 生成CSR */
    std::shared_ptr<X509_REQ> rootReq(X509_REQ_new(), X509_REQ_free);
    /* CSR相关设置 */
    X509_REQ_set_pubkey(rootReq.get(), rootKey.get());

    std::shared_ptr<X509_NAME> rootCAname(X509_NAME_new(), X509_NAME_free);
    unsigned char c[] = "CN";
    unsigned char o[] = "Tongsuo_root";
    unsigned char cn[] = "https://www.yuque.com/tsdoc";
    X509_NAME_add_entry_by_txt(rootCAname.get(), "C", MBSTRING_ASC, c, -1, -1, 0);
    X509_NAME_add_entry_by_txt(rootCAname.get(), "O", MBSTRING_ASC, o, -1, -1, 0);
    X509_NAME_add_entry_by_txt(rootCAname.get(), "CN", MBSTRING_ASC, cn, -1, -1, 0);
    X509_REQ_set_subject_name(rootReq.get(), rootCAname.get());

    X509_REQ_set_version(rootReq.get(), X509_VERSION_3);
    X509_REQ_sign(rootReq.get(), rootKey.get(), EVP_sm3());
    X509_REQ_verify(rootReq.get(), rootKey.get());

    /* 签发根证书 */
    std::shared_ptr<X509> rootCer(X509_new(), X509_free);
    /* 证书相关设置 */
    X509_set_version(rootCer.get(), X509_VERSION_3);
    X509_set_pubkey(rootCer.get(), rootKey.get());

    std::shared_ptr<ASN1_INTEGER> aserial(ASN1_INTEGER_new(), ASN1_INTEGER_free);
    ASN1_INTEGER_set(aserial.get(), 0);
    X509_set_serialNumber(rootCer.get(), aserial.get());

    X509_set_subject_name(rootCer.get(), rootCAname.get());
    X509_set_issuer_name(rootCer.get(), rootCAname.get());

    time_t curTime = time(NULL);
    std::shared_ptr<ASN1_TIME> rootBeforeTime(ASN1_TIME_new(), ASN1_TIME_free);
    ASN1_TIME_set(rootBeforeTime.get(), curTime);
    X509_set_notBefore(rootCer.get(), rootBeforeTime.get());
    std::shared_ptr<ASN1_TIME> rootAfterTime(ASN1_TIME_adj(NULL, curTime, 0, 3650 * 60 * 60 * 24),
                                             ASN1_TIME_free);
    X509_set_notAfter(rootCer.get(), rootAfterTime.get());
    /* 根密钥自签 */
    X509_sign(rootCer.get(), rootKey.get(), EVP_sm3());
    return rootCer;
}

std::shared_ptr<X509> Sm2Cert::genMidCA(std::shared_ptr<X509> rootCA)
{
    /* 生成中间密钥 */
    std::shared_ptr<EVP_PKEY> midKey(EVP_PKEY_Q_keygen(NULL, NULL, "SM2"), EVP_PKEY_free);
    if (midKey.get() == NULL) {
        /* 错误处理 */
        getError();
        exit(0);
    }
    /* 生成CSR */
    std::shared_ptr<X509_REQ> midReq(X509_REQ_new(), X509_REQ_free);
    /* CSR相关设置 */
    X509_REQ_set_pubkey(midReq.get(), midKey.get());

    std::shared_ptr<X509_NAME> midCAname(X509_NAME_new(), X509_NAME_free);
    unsigned char c[] = "CN";
    unsigned char o[] = "Tongsuo_mid";
    unsigned char cn[] = "https://www.yuque.com/tsdoc";
    X509_NAME_add_entry_by_txt(midCAname.get(), "C", MBSTRING_ASC, c, -1, -1, 0);
    X509_NAME_add_entry_by_txt(midCAname.get(), "O", MBSTRING_ASC, o, -1, -1, 0);
    X509_NAME_add_entry_by_txt(midCAname.get(), "CN", MBSTRING_ASC, cn, -1, -1, 0);
    X509_REQ_set_subject_name(midReq.get(), midCAname.get());

    X509_REQ_set_version(midReq.get(), X509_VERSION_3);
    X509_REQ_sign(midReq.get(), midKey.get(), EVP_sm3());
    X509_REQ_verify(midReq.get(), midKey.get());

    /* 签发证书 */
    std::shared_ptr<X509> midCer(X509_new(), X509_free);
    /* 证书相关设置 */
    X509_set_version(midCer.get(), X509_VERSION_3);
    X509_set_pubkey(midCer.get(), midKey.get());
    std::shared_ptr<ASN1_INTEGER> aserial(ASN1_INTEGER_new(), ASN1_INTEGER_free);
    ASN1_INTEGER_set(aserial.get(), 0);
    X509_set_serialNumber(midCer.get(), aserial.get());
    X509_set_subject_name(midCer.get(), midCAname.get());

    const X509_NAME *rootCAname = X509_get_subject_name(rootCA.get());
    X509_set_issuer_name(midCer.get(), rootCAname);

    time_t curTime = time(NULL);
    std::shared_ptr<ASN1_TIME> rootBeforeTime(ASN1_TIME_new(), ASN1_TIME_free);
    ASN1_TIME_set(rootBeforeTime.get(), curTime);
    X509_set_notBefore(midCer.get(), rootBeforeTime.get());
    std::shared_ptr<ASN1_TIME> rootAfterTime(ASN1_TIME_adj(NULL, curTime, 0, 3650 * 60 * 60 * 24),
                                             ASN1_TIME_free);
    X509_set_notAfter(midCer.get(), rootAfterTime.get());
    std::shared_ptr<EVP_PKEY> rootKey(X509_get_pubkey(rootCA.get()), EVP_PKEY_free);
    /* 使用根CA私钥签发 */
    X509_sign(midCer.get(), rootKey.get(), EVP_sm3());
    return midCer;
}

std::shared_ptr<X509> Sm2Cert::genEncryptCert(std::shared_ptr<X509> midCA,
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
    this->ui->textBrowserEncryKey->setText(QString(buf));
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
    std::string str = "Key Encipherment, Data Encipherment";
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
    /* 使用中间CA签发 */
    std::shared_ptr<EVP_PKEY> rootKey(X509_get_pubkey(midCA.get()), EVP_PKEY_free);
    X509_sign(userCer.get(), rootKey.get(), EVP_sm3());

    return userCer;
}

std::shared_ptr<X509> Sm2Cert::genSignCert(std::shared_ptr<X509> midCA, QString CNname, QString days)
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
    this->ui->textBrowserSignKey->setText(QString(buf));
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
    std::string str = "Digital Signature";
    std::shared_ptr<X509_EXTENSION>
        cert_ex(X509V3_EXT_conf_nid(NULL, NULL, NID_key_usage, str.c_str()), X509_EXTENSION_free);
    X509_add_ext(userCer.get(), cert_ex.get(), -1);
    //Key Encipherment, Data Encipherment
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
    /* 使用中间CA签发 */
    std::shared_ptr<EVP_PKEY> rootKey(X509_get_pubkey(midCA.get()), EVP_PKEY_free);
    X509_sign(userCer.get(), rootKey.get(), EVP_sm3());

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

    /* 生成根CA证书 */
    std::shared_ptr<X509> rootCer = this->genRootCA();
    /* 生成中间CA证书 */
    std::shared_ptr<X509> midCer = this->genMidCA(rootCer);
    /* 生成用户签名证书 */
    std::shared_ptr<X509> userSignCer = this->genSignCert(midCer, CN, days);
    /* 生成用户加密证书 */
    std::shared_ptr<X509> userEncryptCer = this->genEncryptCert(midCer, CN, days);
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
