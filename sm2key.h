#ifndef SM2KEY_H
#define SM2KEY_H

#include "tserror.h"
#include <memory>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <string.h>
#include <string>
#include <QWidget>

namespace Ui {
class Sm2Key;
}

class Sm2Key : public QWidget
{
    Q_OBJECT

public:
    explicit Sm2Key(QWidget *parent = nullptr);
    ~Sm2Key();

private slots:
    void on_pushButtonGen_clicked();

private:
    Ui::Sm2Key *ui;
};

#endif // SM2KEY_H
