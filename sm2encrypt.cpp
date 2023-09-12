#include "sm2encrypt.h"
#include "ui_sm2encrypt.h"

Sm2Encrypt::Sm2Encrypt(QWidget *parent)
    : QWidget(parent)
    , ui(new Ui::Sm2Encrypt)
{
    ui->setupUi(this);
}

Sm2Encrypt::~Sm2Encrypt()
{
    delete ui;
}

void Sm2Encrypt::on_pushButtonEncrypt_clicked()
{
    /* 选定椭圆曲线组 */
    std::shared_ptr<EC_GROUP> group(EC_GROUP_new_by_curve_name(NID_sm2), EC_GROUP_free);
    /* 密钥上下文生成 */
    std::shared_ptr<EC_KEY> eckey(EC_KEY_new(), EC_KEY_free);
    /* 设定密钥的曲线组 */
    EC_KEY_set_group(eckey.get(), group.get());
    /* 获取用户输入的公钥 */
    QString pubQstrInput = this->ui->lineEditPub->text();
    /* 将16进制字符串公钥转为EC_POINT，并设置到EC_KEY */
    const EC_POINT *pubPoint
        = EC_POINT_hex2point(group.get(), pubQstrInput.toStdString().c_str(), NULL, NULL);
    EC_KEY_set_public_key(eckey.get(), pubPoint);
    /* 将EC_KEY设置到EVP_PKEY */
    std::shared_ptr<EVP_PKEY> pKey(EVP_PKEY_new(), EVP_PKEY_free);
    EVP_PKEY_set1_EC_KEY(pKey.get(), eckey.get());
    /* 生成加密上下文 */
    std::shared_ptr<EVP_PKEY_CTX> pkCtx(EVP_PKEY_CTX_new(pKey.get(), NULL), EVP_PKEY_CTX_free);
    /* 加密初始化 */
    if (EVP_PKEY_encrypt_init(pkCtx.get()) <= 0) {
        getError();
        return;
    }
    /* 获取输入明文 */
    QString plainTextQstr = this->ui->plainTextEditInput->toPlainText();
    /* 获取加密密文长度 */
    size_t cipherTextLen = 0;
    int res = EVP_PKEY_encrypt(pkCtx.get(),
                               NULL,
                               &cipherTextLen,
                               (const unsigned char *) plainTextQstr.toStdString().c_str(),
                               plainTextQstr.size());
    if (res != 1) {
        getError();
        return;
    }
    /* 加密生成密文 */
    std::shared_ptr<unsigned char> cipherText(new unsigned char[cipherTextLen]);
    res = EVP_PKEY_encrypt(pkCtx.get(),
                           cipherText.get(),
                           &cipherTextLen,
                           (const unsigned char *) plainTextQstr.toStdString().c_str(),
                           plainTextQstr.size());
    if (res != 1) {
        getError();
        return;
    }
    /* 以16进制字符串的形式显示在输出框 */
    std::shared_ptr<char> outBuf(OPENSSL_buf2hexstr(cipherText.get(), cipherTextLen),
                                 [](char *outbuf) { OPENSSL_free(outbuf); });
    this->ui->plainTextEditOutput->setPlainText(QString(outBuf.get()));
}

void Sm2Encrypt::on_pushButtonDecrypt_clicked()
{
    /* 选定椭圆曲线组 */
    std::shared_ptr<EC_GROUP> group(EC_GROUP_new_by_curve_name(NID_sm2), EC_GROUP_free);
    /* 密钥上下文生成 */
    std::shared_ptr<EC_KEY> ecKey(EC_KEY_new(), EC_KEY_free);
    /* 设定密钥的曲线组 */
    EC_KEY_set_group(ecKey.get(), group.get());
    /* 获取用户输入的私钥 */
    QString priQstrInput = this->ui->lineEditPri->text();
    /* 将16进制字符串私钥转为BIGNUM，并设置到EC_KEY */
    BIGNUM *priBn = BN_new();
    BN_hex2bn(&priBn, priQstrInput.toStdString().c_str());
    EC_KEY_set_private_key(ecKey.get(), priBn);
    BN_free(priBn);
    /* 将EC_KEY设置到EVP_PKEY */
    std::shared_ptr<EVP_PKEY> pKey(EVP_PKEY_new(), EVP_PKEY_free);
    EVP_PKEY_set1_EC_KEY(pKey.get(), ecKey.get());
    /* 生成解密上下文 */
    std::shared_ptr<EVP_PKEY_CTX> pkCtx(EVP_PKEY_CTX_new(pKey.get(), NULL), EVP_PKEY_CTX_free);
    /* 解密初始化 */
    if (EVP_PKEY_decrypt_init(pkCtx.get()) <= 0) {
        getError();
        return;
    }
    /* 获取输入密文 */
    QString cipherTextQstr = this->ui->plainTextEditInput->toPlainText();
    long inBufLen = 0;
    const unsigned char *inBuf = OPENSSL_hexstr2buf(cipherTextQstr.toStdString().c_str(), &inBufLen);
    /* 获取解密明文长度 */
    size_t plainTextLen = 0;
    EVP_PKEY_decrypt(pkCtx.get(), NULL, &plainTextLen, inBuf, inBufLen);
    /* 解密 生成明文 */
    std::shared_ptr<unsigned char> plainText(new unsigned char[plainTextLen]);
    EVP_PKEY_decrypt(pkCtx.get(), plainText.get(), &plainTextLen, inBuf, inBufLen);
    /* 将明文内容显示到输出框 */
    std::string outStr((const char *) plainText.get(), plainTextLen);
    this->ui->plainTextEditOutput->setPlainText(QString::fromStdString(outStr));
}
