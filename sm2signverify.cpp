#include "sm2signverify.h"
#include "sm2.h"
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
    EVP_PKEY *pkey = NULL;
    std::string hex;

    pkey = EVP_PKEY_Q_keygen(NULL, NULL, "SM2");
    if (pkey == NULL) {
        printTSError();
        goto end;
    }

    if (!sm2_key_get_pub_hex(pkey, hex)) {
        printTSError();
        goto end;
    }

    this->ui->plainTextEditPubKey->setPlainText(QString::fromStdString(hex));

    if (!sm2_key_get_priv_hex(pkey, hex)) {
        printTSError();
        goto end;
    }

    this->ui->lineEditPriKey->setText(QString::fromStdString(hex));

end:
    EVP_PKEY_free(pkey);
    return;
}

void Sm2SignVerify::on_pushButtonSign_clicked()
{
    /* 获取私钥 */
    QString pubQstr = this->ui->plainTextEditPubKey->toPlainText();
    QString priQstr = this->ui->lineEditPriKey->text();
    QString inputQstr = this->ui->textEditData->toPlainText();
    EVP_PKEY *pkey = NULL;
    EVP_MD_CTX *mctx = NULL;
    size_t siglen = 0;
    std::vector<unsigned char> sig;
    std::vector<char> str;

    if (priQstr.isEmpty()) {
        QMessageBox::warning(NULL,
                             "warning",
                             QString("请输入或生成私钥！"),
                             QMessageBox::Close,
                             QMessageBox::Close);
        return;
    }

    if (inputQstr.isEmpty()) {
        QMessageBox::warning(NULL,
                             "warning",
                             QString("请输入待签名数据！"),
                             QMessageBox::Close,
                             QMessageBox::Close);
        return;
    }

    pkey = sm2_key_new_from_raw_pub_and_priv(pubQstr.toStdString(), priQstr.toStdString());
    if (pkey == NULL) {
        printTSError();
        return;
    }

    mctx = EVP_MD_CTX_new();
    if (mctx == NULL)
        goto end;

    if (!EVP_DigestSignInit(mctx, NULL, EVP_sm3(), NULL, pkey)
        || !EVP_DigestSign(mctx,
                           NULL,
                           &siglen,
                           (unsigned char *) inputQstr.toStdString().c_str(),
                           inputQstr.size())) {
        printTSError();
        goto end;
    }

    sig.reserve(siglen);

    if (EVP_DigestSign(mctx,
                       sig.data(),
                       &siglen,
                       (unsigned char *) inputQstr.toStdString().c_str(),
                       inputQstr.size())
        != 1) {
        printTSError();
        goto end;
    }

    str.reserve(siglen * 2 + 1);

    if (OPENSSL_buf2hexstr_ex(str.data(), str.capacity(), NULL, sig.data(), siglen, '\0') != 1) {
        printTSError();
        goto end;
    }

    this->ui->plainTextEditSign->setPlainText(
        QString::fromStdString(std::string(str.data(), str.capacity())));
end:
    EVP_MD_CTX_free(mctx);
    EVP_PKEY_free(pkey);
    return;
}

void Sm2SignVerify::on_pushButtonVerify_clicked()
{
    QString pubQstrInput = this->ui->plainTextEditPubKey->toPlainText();
    QString inputQstr = this->ui->textEditData->toPlainText();
    QString signQstr = this->ui->plainTextEditSign->toPlainText();
    std::vector<unsigned char> sig;
    EVP_PKEY *pkey = NULL;
    EVP_MD_CTX *mctx = NULL;
    int ret;

    if (pubQstrInput.isEmpty()) {
        QMessageBox::warning(NULL,
                             "warning",
                             QString("请输入公钥！"),
                             QMessageBox::Close,
                             QMessageBox::Close);
        return;
    }

    if (signQstr.isEmpty()) {
        QMessageBox::warning(NULL,
                             "warning",
                             QString("请输入签名！"),
                             QMessageBox::Close,
                             QMessageBox::Close);
        return;
    }

    sig.reserve(signQstr.size() / 2);

    if (OPENSSL_hexstr2buf_ex(sig.data(), sig.capacity(), NULL, signQstr.toStdString().c_str(), '\0')
        != 1) {
        printTSError();
        goto end;
    }

    pkey = sm2_key_new_from_raw_pub(pubQstrInput.toStdString());
    if (pkey == NULL) {
        printTSError();
        goto end;
    }

    mctx = EVP_MD_CTX_new();
    if (mctx == NULL)
        goto end;

    if (!EVP_DigestVerifyInit(mctx, NULL, EVP_sm3(), NULL, pkey)) {
        printTSError();
        goto end;
    }
    /* 验签 */
    ret = EVP_DigestVerify(mctx,
                           sig.data(),
                           sig.capacity(),
                           (unsigned char *) inputQstr.toStdString().c_str(),
                           inputQstr.size());
    if (ret == 1) {
        QMessageBox::information(NULL,
                                 "success",
                                 QString("验签成功！"),
                                 QMessageBox::Close,
                                 QMessageBox::Close);
    } else if (ret == 0) {
        QMessageBox::warning(NULL,
                             "failed",
                             QString("验签失败！"),
                             QMessageBox::Close,
                             QMessageBox::Close);
    } else {
        getError();
        return;
    }
end:
    EVP_MD_CTX_free(mctx);
    EVP_PKEY_free(pkey);
    return;
}
