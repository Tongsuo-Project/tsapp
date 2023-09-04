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
    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_sm2);
    /* 给EC_KEY设定曲线组*/
    EC_KEY *ecKey = EC_KEY_new();
    EC_KEY_set_group(ecKey, group);
    /* 获取用户输入的公钥 */
    QString pubQstrInput = this->ui->lineEditPub->text();
    /* 将16进制字符串公钥转为EC_POINT，并设置到EC_KEY */
    EC_POINT *pubPoint = EC_POINT_hex2point(group, pubQstrInput.toStdString().c_str(), NULL, NULL);
    EC_KEY_set_public_key(ecKey, pubPoint);
    /* 将EC_KEY设置到EVP_PKEY */
    EVP_PKEY *pKey = EVP_PKEY_new();
    EVP_PKEY_set1_EC_KEY(pKey, ecKey);
    /* 生成加密上下文 */
    EVP_PKEY_CTX *pkCtx = EVP_PKEY_CTX_new(pKey, NULL);
    /* 加密初始化 */
    EVP_PKEY_encrypt_init(pkCtx);
    /* 获取输入明文 */
    QString plainTextQstr = this->ui->plainTextEditInput->toPlainText();
    //const unsigned char *plainTextIn = (const unsigned char *) plainTextQstr.toStdString().c_str();
    /* 获取加密密文长度 */
    size_t cipherTextLen = 0;
    EVP_PKEY_encrypt(pkCtx,
                     NULL,
                     &cipherTextLen,
                     (const unsigned char *) plainTextQstr.toStdString().c_str(),
                     plainTextQstr.size());
    /* 加密生成密文 */
    unsigned char *cipherText = new unsigned char[cipherTextLen];
    EVP_PKEY_encrypt(pkCtx,
                     cipherText,
                     &cipherTextLen,
                     (const unsigned char *) plainTextQstr.toStdString().c_str(),
                     plainTextQstr.size());
    /* 以16进制字符串的形式显示在输出框 */
    char *outBuf = OPENSSL_buf2hexstr(cipherText, cipherTextLen);
    this->ui->plainTextEditOutput->setPlainText(QString(outBuf));
    /* 释放内存资源 */
    OPENSSL_free(outBuf);
    delete[] cipherText;
    EVP_PKEY_CTX_free(pkCtx);
    EVP_PKEY_free(pKey);
    EC_POINT_free(pubPoint);
    EC_GROUP_free(group);
    EC_KEY_free(ecKey);
}

void Sm2Encrypt::on_pushButtonDecrypt_clicked()
{
    /* 选定椭圆曲线组 */
    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_sm2);
    /* 给EC_KEY设定曲线组 */
    EC_KEY *ecKey = EC_KEY_new();
    EC_KEY_set_group(ecKey, group);
    /* 获取用户输入的私钥 */
    QString priQstrInput = this->ui->lineEditPri->text();
    /* 将16进制字符串私钥转为BIGNUM，并设置到EC_KEY */
    BIGNUM *priBn = BN_new();
    BN_hex2bn(&priBn, priQstrInput.toStdString().c_str());
    EC_KEY_set_private_key(ecKey, priBn);
    /* 将EC_KEY设置到EVP_PKEY */
    EVP_PKEY *pKey = EVP_PKEY_new();
    EVP_PKEY_set1_EC_KEY(pKey, ecKey);
    /* 生成解密上下文 */
    EVP_PKEY_CTX *pkCtx = EVP_PKEY_CTX_new(pKey, NULL);
    /* 解密初始化 */
    EVP_PKEY_decrypt_init(pkCtx);
    /* 获取输入密文 */
    QString cipherTextQstr = this->ui->plainTextEditInput->toPlainText();
    long inBufLen = 0;
    const unsigned char *inBuf = OPENSSL_hexstr2buf(cipherTextQstr.toStdString().c_str(), &inBufLen);
    /* 获取解密明文长度 */
    size_t plainTextLen = 0;
    EVP_PKEY_decrypt(pkCtx, NULL, &plainTextLen, inBuf, inBufLen);
    /* 解密 生成明文 */
    unsigned char *plainText = new unsigned char[plainTextLen];
    EVP_PKEY_decrypt(pkCtx, plainText, &plainTextLen, inBuf, inBufLen);
    /* 将明文内容显示到输出框 */
    std::string outStr((const char *) plainText, plainTextLen);
    this->ui->plainTextEditOutput->setPlainText(QString::fromStdString(outStr));
    /* 释放内存资源 */
    delete[] plainText;
    EVP_PKEY_CTX_free(pkCtx);
    EVP_PKEY_free(pKey);
    BN_free(priBn);
    EC_GROUP_free(group);
    EC_KEY_free(ecKey);
}
