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
#include <stdio.h>
#include <string>
#include <time.h>
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
    int addExtension(X509 *cert, X509 *root, int nid, const char *value);
    std::shared_ptr<X509> genRootCA();
    std::shared_ptr<X509> genMidCA(std::shared_ptr<X509> rootCA);
    std::shared_ptr<X509> genSignCert(std::shared_ptr<X509> midCA, QString CNname, QString days);
    std::shared_ptr<X509> genEncryptCert(std::shared_ptr<X509> midCA, QString CNname, QString days);
};

#endif // SM2CERT_H
