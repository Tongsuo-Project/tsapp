#include "sm2encrypt.h"
#include "sm2.h"
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
    QString input = this->ui->textEditPlain->toPlainText();
    QString pubQstrInput = this->ui->plainTextEditPub->toPlainText();
    EVP_PKEY_CTX *encctx = NULL;
    EVP_PKEY *pkey = NULL;
    size_t outlen;
    std::vector<unsigned char> buf;
    std::vector<char> str;

    if (pubQstrInput.isEmpty()) {
        QMessageBox::warning(NULL,
                             "warning",
                             QString("请输入公钥！"),
                             QMessageBox::Close,
                             QMessageBox::Close);
        return;
    }

    if (input.isEmpty()) {
        QMessageBox::warning(NULL,
                             "warning",
                             QString("请输入明文！"),
                             QMessageBox::Close,
                             QMessageBox::Close);
        return;
    }

    pkey = sm2_key_new_from_raw_pub(pubQstrInput.toStdString());
    if (pkey == NULL) {
        printTSError();
        goto end;
    }

    encctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
    if (encctx == NULL)
        goto end;

    if (EVP_PKEY_encrypt_init(encctx) <= 0
        || EVP_PKEY_encrypt(encctx,
                            NULL,
                            &outlen,
                            (const unsigned char *) input.toStdString().c_str(),
                            input.toStdString().length())
               <= 0)
        goto end;

    buf.clear();
    buf.reserve(outlen);

    if (EVP_PKEY_encrypt(encctx,
                         buf.data(),
                         &outlen,
                         (const unsigned char *) input.toStdString().c_str(),
                         input.toStdString().length())
        <= 0)
        goto end;

    str.reserve(outlen * 2 + 1);
    if (OPENSSL_buf2hexstr_ex(str.data(), str.capacity(), NULL, buf.data(), outlen, '\0') != 1) {
        printTSError();
        goto end;
    }

    this->ui->textEditCipher->setText(QString::fromStdString(std::string(str.data(), outlen * 2)));

end:
    EVP_PKEY_free(pkey);
}

void Sm2Encrypt::on_pushButtonDecrypt_clicked()
{
    QString input = this->ui->textEditCipher->toPlainText();
    QString pubQstrInput = this->ui->plainTextEditPub->toPlainText();
    QString privQstrInput = this->ui->plainTextEditPriv->toPlainText();
    EVP_PKEY_CTX *encctx = NULL;
    EVP_PKEY *pkey = NULL;
    size_t outlen;
    std::vector<unsigned char> buf;
    std::vector<char> str;

    if (pubQstrInput.isEmpty() || privQstrInput.isEmpty()) {
        QMessageBox::warning(NULL,
                             "warning",
                             QString("请输入公钥和私钥！"),
                             QMessageBox::Close,
                             QMessageBox::Close);
        return;
    }

    if (input.isEmpty()) {
        QMessageBox::warning(NULL,
                             "warning",
                             QString("请输入密文！"),
                             QMessageBox::Close,
                             QMessageBox::Close);
        return;
    }

    pkey = sm2_key_new_from_raw_pub_and_priv(pubQstrInput.toStdString(),
                                             privQstrInput.toStdString());
    if (pkey == NULL) {
        printTSError();
        goto end;
    }

    encctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
    if (encctx == NULL)
        goto end;

    buf.clear();
    buf.reserve(input.length() / 2);

    if (OPENSSL_hexstr2buf_ex(buf.data(), buf.capacity(), NULL, input.toStdString().c_str(), '\0')
        != 1) {
        printTSError();
        goto end;
    }

    if (EVP_PKEY_decrypt_init(encctx) <= 0
        || EVP_PKEY_decrypt(encctx, NULL, &outlen, buf.data(), buf.capacity()) <= 0)
        goto end;

    str.clear();
    str.reserve(outlen);

    if (EVP_PKEY_decrypt(encctx, (unsigned char *) str.data(), &outlen, buf.data(), buf.capacity())
        <= 0)
        goto end;

    this->ui->textEditPlain->setText(QString::fromStdString(std::string(str.data(), outlen)));

end:
    EVP_PKEY_free(pkey);
}

void Sm2Encrypt::on_pushButtonGen_clicked()
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

    this->ui->plainTextEditPub->setPlainText(QString::fromStdString(hex));

    if (!sm2_key_get_priv_hex(pkey, hex)) {
        printTSError();
        goto end;
    }

    this->ui->plainTextEditPriv->setPlainText(QString::fromStdString(hex));

end:
    EVP_PKEY_free(pkey);
    return;
}
