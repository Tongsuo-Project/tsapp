#ifndef SM2KEY_H
#define SM2KEY_H
#include <QWidget>
#include <openssl/evp.h>
#include "openssl/ec.h"
#include <openssl/x509.h>
#include <openssl/err.h>

namespace Ui {
class Sm2Key;
}

class Sm2Key : public QWidget
{
    Q_OBJECT

public:
    explicit Sm2Key(QWidget *parent = nullptr);
    ~Sm2Key();
    EC_KEY *genSm2Key();

private slots:
    void on_pushButtonGen_clicked();

private:
    Ui::Sm2Key *ui;
};

#endif // SM2KEY_H
