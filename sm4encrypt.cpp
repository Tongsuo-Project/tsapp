#include "sm4encrypt.h"
#include "ui_sm4encrypt.h"

Sm4encrypt::Sm4encrypt(QWidget *parent)
    : QWidget(parent)
    , ui(new Ui::Sm4encrypt)
{
    ui->setupUi(this);
}

Sm4encrypt::~Sm4encrypt()
{
    delete ui;
}

void Sm4encrypt::on_pushButtonGen_clicked()
{
    /* 获取密钥 */
    QString keyQstr = this->ui->lineEditKey->text();
    long keyLen = keyQstr.size();
    std::shared_ptr<unsigned char> key(OPENSSL_hexstr2buf(keyQstr.toStdString().c_str(), &keyLen),
                                       [](unsigned char *buf) { OPENSSL_free(buf); });
    /* 获取加密内容 */
    QString inputQstr = this->ui->plainTextEditInput->toPlainText();
    /* 生成加密上下文 */
    std::shared_ptr<EVP_CIPHER_CTX> sm4Ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    if (sm4Ctx == NULL) {
        /* 错误处理 */
        getError();
        return;
    }
    /* 选定模式初始化加密 */
    int modeIndex = this->ui->comboBoxMode->currentIndex();
    if (modeIndex == 0) {
        /* CBC模式 */
        QString ivQstr = this->ui->lineEditCBCIV->text();
        long ivlen = ivQstr.size();
        std::shared_ptr<unsigned char> iv(OPENSSL_hexstr2buf(ivQstr.toStdString().c_str(), &ivlen),
                                          [](unsigned char *buf) { OPENSSL_free(buf); });
        if (!EVP_EncryptInit(sm4Ctx.get(), EVP_sm4_cbc(), key.get(), iv.get())) {
            /* 错误处理 */
            getError();
            return;
        }
    } else if (modeIndex == 1) {
        /* ECB模式 */
        if (!EVP_EncryptInit(sm4Ctx.get(), EVP_sm4_ecb(), key.get(), NULL)) {
            /* 错误处理 */
            getError();
            return;
        }
    } else {
        getError();
        return;
    }

    /* 加密 */
    int outputLen = 0, tmpLen = 0;
    std::shared_ptr<unsigned char> output(
        new unsigned char[inputQstr.size() + EVP_MAX_BLOCK_LENGTH]);
    if (!EVP_EncryptUpdate(sm4Ctx.get(),
                           output.get(),
                           &outputLen,
                           (unsigned char *) inputQstr.toStdString().c_str(),
                           inputQstr.size())) {
        /* 错误处理 */
        getError();
        return;
    }
    if (!EVP_EncryptFinal(sm4Ctx.get(), output.get() + outputLen, &tmpLen)) {
        /* 错误处理 */
        getError();
        return;
    }
    /* 将加密结果以16进制显示到输出栏 */
    std::shared_ptr<char> outHex(OPENSSL_buf2hexstr(output.get(), outputLen + tmpLen),
                                 [](char *buf) { OPENSSL_free(buf); });
    this->ui->textBrowserOutput->setText(QString(outHex.get()));
}

void Sm4encrypt::on_pushButtonDecrypt_clicked()
{
    /* 获取密钥 */
    QString keyQstr = this->ui->lineEditKey->text();
    long keyLen = keyQstr.size();
    std::shared_ptr<unsigned char> key(OPENSSL_hexstr2buf(keyQstr.toStdString().c_str(), &keyLen),
                                       [](unsigned char *buf) { OPENSSL_free(buf); });
    /* 获取解密内容 */
    QString inputQstr = this->ui->plainTextEditInput->toPlainText();
    long inputlen = inputQstr.size();
    std::shared_ptr<unsigned char> input(OPENSSL_hexstr2buf(inputQstr.toStdString().c_str(),
                                                            &inputlen),
                                         [](unsigned char *buf) { OPENSSL_free(buf); });
    /* 生成解密上下文 */
    std::shared_ptr<EVP_CIPHER_CTX> sm4Ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    if (sm4Ctx == NULL) {
        /* 错误处理 */
        getError();
        return;
    }
    /* 选定模式初始化解密 */
    int modeIndex = this->ui->comboBoxMode->currentIndex();
    if (modeIndex == 0) {
        /* CBC模式 */
        QString ivQstr = this->ui->lineEditCBCIV->text();
        long ivlen = ivQstr.size();
        std::shared_ptr<unsigned char> iv(OPENSSL_hexstr2buf(ivQstr.toStdString().c_str(), &ivlen),
                                          [](unsigned char *buf) { OPENSSL_free(buf); });
        if (!EVP_DecryptInit(sm4Ctx.get(), EVP_sm4_cbc(), key.get(), iv.get())) {
            /* 错误处理 */
            getError();
            return;
        }
    } else if (modeIndex == 1) {
        /* ECB模式 */
        if (!EVP_DecryptInit(sm4Ctx.get(), EVP_sm4_ecb(), key.get(), NULL)) {
            /* 错误处理 */
            getError();
            return;
        }
    } else {
        getError();
        return;
    }
    /* 解密 */
    int outputLen = 0, tmpLen = 0;
    std::shared_ptr<unsigned char> output(new unsigned char[inputlen]);
    if (!EVP_DecryptUpdate(sm4Ctx.get(), output.get(), &outputLen, input.get(), inputlen)) {
        /* 错误处理 */
        getError();
        return;
    }
    if (!EVP_DecryptFinal(sm4Ctx.get(), output.get() + outputLen, &tmpLen)) {
        /* 错误处理 */
        getError();
        return;
    }
    /* 将解密结果显示到输出栏 */
    this->ui->textBrowserOutput->setText(
        QString::asprintf("%.*s", outputLen + tmpLen, output.get()));
}
