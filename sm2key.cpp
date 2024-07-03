#include "sm2key.h"
#include "sm2.h"
#include "ui_sm2key.h"

Sm2Key::Sm2Key(QWidget *parent)
    : QWidget(parent)
    , ui(new Ui::Sm2Key)
{
    ui->setupUi(this);
}

Sm2Key::~Sm2Key()
{
    delete ui;
}

void Sm2Key::on_pushButtonGen_clicked()
{
    EVP_PKEY *pkey = NULL;
    std::string pem, hex;

    pkey = EVP_PKEY_Q_keygen(NULL, NULL, "SM2");
    if (pkey == NULL) {
        printTSError();
        goto end;
    }

    if (!sm2_key_get_priv_pem(pkey, pem)) {
        printTSError();
        goto end;
    }

    this->ui->textBrowserPrivPem->setText(QString::fromStdString(pem));

    if (!sm2_key_get_pub_pem(pkey, pem)) {
        printTSError();
        goto end;
    }

    this->ui->textBrowserPubPem->setText(QString::fromStdString(pem));

    if (!sm2_key_get_pub_hex(pkey, hex)) {
        printTSError();
        goto end;
    }

    this->ui->textBrowserPubkey->setText(QString::fromStdString(hex));

    if (!sm2_key_get_priv_hex(pkey, hex)) {
        printTSError();
        goto end;
    }

    this->ui->textBrowserPrivkey->setText(QString::fromStdString(hex));

end:
    EVP_PKEY_free(pkey);
    return;
}
