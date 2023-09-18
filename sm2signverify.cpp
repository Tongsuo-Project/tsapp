#include "sm2signverify.h"
#include "ui_sm2signverify.h"

Sm2SignVerify::Sm2SignVerify(QWidget *parent)
    : QWidget(parent)
    , ui(new Ui::Sm2SignVerify)
{
    ui->setupUi(this);
}

Sm2SignVerify::~Sm2SignVerify()
{
    delete ui;
}

void Sm2SignVerify::on_pushButtonGenKey_clicked()
{
    /* 选定椭圆曲线组 */
    std::shared_ptr<EC_GROUP> group(EC_GROUP_new_by_curve_name(NID_sm2), EC_GROUP_free);
    if (!group) {
        getError();
        return;
    }
    /* 密钥上下文生成 */
    std::shared_ptr<EC_KEY> key(EC_KEY_new(), EC_KEY_free);
    /* 设定密钥的曲线组 */
    EC_KEY_set_group(key.get(), group.get());
    /* 生成EC_KEY */
    int res = EC_KEY_generate_key(key.get());
    if (res != 1) {
        getError();
        return;
    }
    /* 取公钥并转换为十六进制字符串 */
    const EC_POINT *pubPoint = EC_KEY_get0_public_key(key.get());
    std::shared_ptr<char> pubHexStr(EC_POINT_point2hex(group.get(),
                                                       pubPoint,
                                                       POINT_CONVERSION_UNCOMPRESSED,
                                                       NULL),
                                    [](char *pub) { OPENSSL_free(pub); });
    /* 取私钥并转换为十六进制字符串 */
    const BIGNUM *priBn = EC_KEY_get0_private_key(key.get());
    std::shared_ptr<char> priHexStr(BN_bn2hex(priBn), [](char *pri) { OPENSSL_free(pri); });
    /* 在浏览框中显示公钥和私钥 */
    this->ui->lineEditPriKey->setText(QString(priHexStr.get()));
    this->ui->plainTextEditPubKey->setPlainText(QString(pubHexStr.get()));
}

void Sm2SignVerify::on_pushButtonSign_clicked()
{
    /* 获取私钥 */
    QString priQstr = this->ui->lineEditPriKey->text();
    if (priQstr.isEmpty()) {
        QMessageBox::warning(NULL,
                             "warning",
                             QString("请输入或者生成私钥！"),
                             QMessageBox::Close,
                             QMessageBox::Close);
        return;
    }
    /* 获取待签名数据 */
    QString inputQstr = this->ui->lineEditInput->text();
    if (inputQstr.isEmpty()) {
        QMessageBox::warning(NULL,
                             "warning",
                             QString("请输入待签数据！"),
                             QMessageBox::Close,
                             QMessageBox::Close);
        return;
    }

    /* 选定椭圆曲线组 */
    std::shared_ptr<EC_GROUP> group(EC_GROUP_new_by_curve_name(NID_sm2), EC_GROUP_free);
    /* EC密钥生成 */
    std::shared_ptr<EC_KEY> ecKey(EC_KEY_new(), EC_KEY_free);
    /* 设定密钥的曲线组 */
    EC_KEY_set_group(ecKey.get(), group.get());
    /* 将16进制字符串私钥转为BIGNUM，并设置到EC_KEY */
    BIGNUM *priBn = BN_new();
    BN_hex2bn(&priBn, priQstr.toStdString().c_str());
    EC_KEY_set_private_key(ecKey.get(), priBn);
    BN_free(priBn);
    /* 将EC_KEY设置到EVP_PKEY */
    std::shared_ptr<EVP_PKEY> pKey(EVP_PKEY_new(), EVP_PKEY_free);
    EVP_PKEY_set1_EC_KEY(pKey.get(), ecKey.get());

    /* 进行哈希生成摘要 */
    size_t siglen = 0;
    unsigned char md[32] = {};
    size_t mdlen = 0;
    if (!EVP_Q_digest(
            NULL, "SM3", NULL, inputQstr.toStdString().c_str(), inputQstr.size(), md, &mdlen)) {
        /* 错误处理 */
        getError();
        return;
    }
    /*对数据签名*/
    std::shared_ptr<EVP_PKEY_CTX> pctx(EVP_PKEY_CTX_new(pKey.get(), NULL), EVP_PKEY_CTX_free);
    if (pctx == NULL) {
        /* 错误处理 */
        getError();
        return;
    }
    if (EVP_PKEY_sign_init(pctx.get()) <= 0) {
        /* 错误处理 */
        getError();
        return;
    }
    if (EVP_PKEY_sign(pctx.get(), NULL, &siglen, md, mdlen) <= 0) {
        /* 错误处理 */
        getError();
        return;
    }
    std::shared_ptr<unsigned char> sig((unsigned char *) OPENSSL_malloc(siglen),
                                       [](unsigned char *buf) { OPENSSL_free(buf); });
    if (sig == NULL) {
        /* 错误处理 */
        getError();
        return;
    }
    if (EVP_PKEY_sign(pctx.get(), sig.get(), &siglen, md, mdlen) <= 0) {
        /* 错误处理 */
        getError();
        return;
    }
    /* 显示十六进制字符串到输出框 */
    std::shared_ptr<char> out(OPENSSL_buf2hexstr(sig.get(), siglen),
                              [](char *buf) { OPENSSL_free(buf); });
    this->ui->plainTextEditOutput->setPlainText(QString(out.get()));
}

void Sm2SignVerify::on_pushButtonVerify_clicked()
{
    /* 获取原文 */
    QString inputQstr = this->ui->lineEditInput->text();
    /* 获取签名 */
    QString signQstr = this->ui->plainTextEditOutput->toPlainText();
    /* 进行哈希生成摘要 */
    unsigned char md[32] = {};
    size_t mdlen = 0;
    if (!EVP_Q_digest(
            NULL, "SM3", NULL, inputQstr.toStdString().c_str(), inputQstr.size(), md, &mdlen)) {
        /* 错误处理 */
        getError();
        return;
    }

    /* 选定椭圆曲线组 */
    std::shared_ptr<EC_GROUP> group(EC_GROUP_new_by_curve_name(NID_sm2), EC_GROUP_free);
    /* 密钥上下文生成 */
    std::shared_ptr<EC_KEY> eckey(EC_KEY_new(), EC_KEY_free);
    /* 设定密钥的曲线组 */
    EC_KEY_set_group(eckey.get(), group.get());
    /* 获取用户输入的公钥 */
    QString pubQstrInput = this->ui->plainTextEditPubKey->toPlainText();
    /* 将16进制字符串公钥转为EC_POINT，并设置到EC_KEY */
    const EC_POINT *pubPoint
        = EC_POINT_hex2point(group.get(), pubQstrInput.toStdString().c_str(), NULL, NULL);
    EC_KEY_set_public_key(eckey.get(), pubPoint);
    /* 将EC_KEY设置到EVP_PKEY */
    std::shared_ptr<EVP_PKEY> pKey(EVP_PKEY_new(), EVP_PKEY_free);
    EVP_PKEY_set1_EC_KEY(pKey.get(), eckey.get());

    /*验签*/
    std::shared_ptr<EVP_PKEY_CTX> pctx(EVP_PKEY_CTX_new(pKey.get(), NULL), EVP_PKEY_CTX_free);
    if (pctx == NULL) {
        /* 错误处理 */
        getError();
        return;
    }
    if (EVP_PKEY_verify_init(pctx.get()) <= 0) {
        /* 错误处理 */
        getError();
        return;
    }
    long siglen = signQstr.size();
    std::shared_ptr<unsigned char> sig(OPENSSL_hexstr2buf(signQstr.toStdString().c_str(), &siglen),
                                       [](unsigned char *buf) { OPENSSL_free(buf); });
    int ret = EVP_PKEY_verify(pctx.get(), sig.get(), siglen, md, mdlen);
    if (ret == 1) {
        /* 验签成功 */
        QMessageBox::warning(NULL,
                             "warning",
                             QString("验签成功！"),
                             QMessageBox::Close,
                             QMessageBox::Close);
    } else if (ret == 0) {
        /* 验签失败 */
        QMessageBox::warning(NULL,
                             "warning",
                             QString("验签失败！"),
                             QMessageBox::Close,
                             QMessageBox::Close);
    } else {
        /* 发生错误 */
        getError();
        return;
    }
}
