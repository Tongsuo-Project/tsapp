#ifndef SM4ENCRYPT_H
#define SM4ENCRYPT_H

#include "tserror.h"
#include <memory>
#include <openssl/evp.h>
#include <QWidget>
namespace Ui {
class Sm4encrypt;
}

class Sm4encrypt : public QWidget
{
    Q_OBJECT

public:
    explicit Sm4encrypt(QWidget *parent = nullptr);
    ~Sm4encrypt();

private slots:
    void on_pushButtonEncrypt_clicked();

    void on_pushButtonDecrypt_clicked();

    void on_pushButtonRandomIV_clicked();

    void on_pushButtonRandomKey_clicked();

    void on_comboBoxMode_currentTextChanged(const QString &arg1);

private:
    Ui::Sm4encrypt *ui;
};

#endif // SM4ENCRYPT_H
