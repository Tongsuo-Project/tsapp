#ifndef SM4ENCRYPT_H
#define SM4ENCRYPT_H

#include <memory>
#include <openssl/evp.h>
#include <tserror.h>
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
    void on_pushButtonGen_clicked();

    void on_pushButtonDecrypt_clicked();

private:
    Ui::Sm4encrypt *ui;
};

#endif // SM4ENCRYPT_H
