#ifndef SM2CERT_H
#define SM2CERT_H

#include "tserror.h"
#include <memory>
#include <openssl/asn1.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <string>
#include <time.h>
#include <QFile>
#include <QWidget>

namespace Ui {
class Sm2Cert;
}

class Sm2Cert : public QWidget
{
    Q_OBJECT

public:
    explicit Sm2Cert(QWidget *parent = nullptr);
    ~Sm2Cert();

private slots:
    void on_pushButtonGen_clicked();

private:
    Ui::Sm2Cert *ui;
};

#endif // SM2CERT_H
