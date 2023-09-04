#ifndef SM2ENCRYPT_H
#define SM2ENCRYPT_H

#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>
#include <string>
#include <QWidget>
#include <QplainTextEdit>

namespace Ui {
class Sm2Encrypt;
}

class Sm2Encrypt : public QWidget
{
    Q_OBJECT

public:
    explicit Sm2Encrypt(QWidget *parent = nullptr);
    ~Sm2Encrypt();

private slots:
    void on_pushButtonEncrypt_clicked();

    void on_pushButtonDecrypt_clicked();

private:
    Ui::Sm2Encrypt *ui;
};

#endif // SM2ENCRYPT_H
