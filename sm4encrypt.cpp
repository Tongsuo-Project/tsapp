#include "sm4encrypt.h"
#include "ui_sm4encrypt.h"
#include <openssl/rand.h>

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

static int do_sm4_crypt(const char *algo,
                        int enc,
                        const unsigned char *key,
                        const unsigned char *iv,
                        const unsigned char *input,
                        size_t inlen,
                        unsigned char *output,
                        size_t *outlen)
{
    int ret = 0;
    EVP_CIPHER_CTX *ctx = NULL;
    EVP_CIPHER *cipher = NULL;
    int len, lenf;

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
        goto end;

    cipher = EVP_CIPHER_fetch(NULL, algo, NULL);
    if (cipher == NULL)
        goto end;

    if (!EVP_CipherInit_ex(ctx, cipher, NULL, key, iv, enc))
        goto end;

    if (!EVP_CipherUpdate(ctx, output, &len, input, inlen))
        goto end;

    if (!EVP_CipherFinal_ex(ctx, output + len, &lenf))
        goto end;

    *outlen = len + lenf;
    ret = 1;
end:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

void Sm4encrypt::on_pushButtonEncrypt_clicked()
{
    QString algo = this->ui->comboBoxMode->currentText();
    QString keyQstr = this->ui->lineEditKey->text();
    QString ivQstr = this->ui->lineEditIV->text();
    QString inputQstr = this->ui->plainTextEditPlain->toPlainText();
    std::vector<unsigned char> key, iv, outbuf;
    std::vector<char> outhex;
    size_t outlen;

    if (keyQstr.isEmpty()) {
        QMessageBox::warning(NULL,
                             "warning",
                             QString("请输入密钥！"),
                             QMessageBox::Close,
                             QMessageBox::Close);
        return;
    }

    if (algo != "SM4-ECB" && ivQstr.isEmpty()) {
        QMessageBox::warning(NULL,
                             "warning",
                             QString("请输入初始化向量IV！"),
                             QMessageBox::Close,
                             QMessageBox::Close);
        return;
    }

    key.reserve(keyQstr.size() / 2);

    if (OPENSSL_hexstr2buf_ex(key.data(), key.capacity(), NULL, keyQstr.toStdString().c_str(), '\0')
        != 1) {
        printTSError();
        return;
    }

    iv.reserve(ivQstr.size() / 2);

    if (OPENSSL_hexstr2buf_ex(iv.data(), iv.capacity(), NULL, ivQstr.toStdString().c_str(), '\0')
        != 1) {
        printTSError();
        return;
    }

    outbuf.reserve(inputQstr.size() + 16);

    if (do_sm4_crypt(algo.toStdString().c_str(),
                     1,
                     key.data(),
                     iv.data(),
                     (const unsigned char *) inputQstr.toStdString().c_str(),
                     inputQstr.size(),
                     outbuf.data(),
                     &outlen)
        != 1) {
        printTSError();
        return;
    }

    outhex.reserve(outlen * 2 + 1);

    if (OPENSSL_buf2hexstr_ex(outhex.data(), outhex.capacity(), NULL, outbuf.data(), outlen, '\0')
        != 1) {
        printTSError();
        return;
    }

    this->ui->plainTextEditCipher->setPlainText(QString(outhex.data()));
}

void Sm4encrypt::on_pushButtonDecrypt_clicked()
{
    QString algo = this->ui->comboBoxMode->currentText();
    QString keyQstr = this->ui->lineEditKey->text();
    QString ivQstr = this->ui->lineEditIV->text();
    QString inputQstr = this->ui->plainTextEditCipher->toPlainText();
    std::vector<unsigned char> key, iv, input;
    std::vector<char> outbuf;
    size_t outlen;

    if (keyQstr.isEmpty()) {
        QMessageBox::warning(NULL,
                             "warning",
                             QString("请输入密钥！"),
                             QMessageBox::Close,
                             QMessageBox::Close);
        return;
    }

    if (algo != "SM4-ECB" && ivQstr.isEmpty()) {
        QMessageBox::warning(NULL,
                             "warning",
                             QString("请输入初始化向量IV！"),
                             QMessageBox::Close,
                             QMessageBox::Close);
        return;
    }

    key.reserve(keyQstr.size() / 2);

    if (OPENSSL_hexstr2buf_ex(key.data(), key.capacity(), NULL, keyQstr.toStdString().c_str(), '\0')
        != 1) {
        printTSError();
        return;
    }

    iv.reserve(ivQstr.size() / 2);

    if (OPENSSL_hexstr2buf_ex(iv.data(), iv.capacity(), NULL, ivQstr.toStdString().c_str(), '\0')
        != 1) {
        printTSError();
        return;
    }

    input.reserve(inputQstr.size() / 2);
    if (OPENSSL_hexstr2buf_ex(input.data(),
                              input.capacity(),
                              NULL,
                              inputQstr.toStdString().c_str(),
                              '\0')
        != 1) {
        printTSError();
        return;
    }

    outbuf.reserve(input.capacity());

    if (do_sm4_crypt(algo.toStdString().c_str(),
                     0,
                     key.data(),
                     iv.data(),
                     input.data(),
                     input.capacity(),
                     (unsigned char *) outbuf.data(),
                     &outlen)
        != 1) {
        printTSError();
        return;
    }

    this->ui->plainTextEditPlain->setPlainText(
        QString::fromStdString(std::string(outbuf.data(), outlen)));
}

void Sm4encrypt::on_pushButtonRandomIV_clicked()
{
    unsigned char buf[16];
    std::vector<char> hex;

    if (RAND_bytes(buf, sizeof(buf)) != 1) {
        printTSError();
        return;
    }

    hex.reserve(sizeof(buf) * 2 + 1);

    if (OPENSSL_buf2hexstr_ex(hex.data(), hex.capacity(), NULL, buf, sizeof(buf), '\0') != 1) {
        printTSError();
        return;
    }

    this->ui->lineEditIV->setText(hex.data());
}

void Sm4encrypt::on_pushButtonRandomKey_clicked()
{
    unsigned char buf[16];
    std::vector<char> hex;

    if (RAND_bytes(buf, sizeof(buf)) != 1) {
        printTSError();
        return;
    }

    hex.reserve(sizeof(buf) * 2 + 1);

    if (OPENSSL_buf2hexstr_ex(hex.data(), hex.capacity(), NULL, buf, sizeof(buf), '\0') != 1) {
        printTSError();
        return;
    }

    this->ui->lineEditKey->setText(hex.data());
}

void Sm4encrypt::on_comboBoxMode_currentTextChanged(const QString &arg1)
{
    if (arg1 == "SM4-ECB") {
        this->ui->lineEditIV->setEnabled(false);
        this->ui->lineEditIV->hide();
    } else {
        this->ui->lineEditIV->setEnabled(true);
        this->ui->lineEditIV->show();
    }
}
