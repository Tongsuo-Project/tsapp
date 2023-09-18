#ifndef SM2SIGNVERIFY_H
#define SM2SIGNVERIFY_H

#include "tserror.h"
#include <memory>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <string.h>
#include <QWidget>
namespace Ui {
class Sm2SignVerify;
}

class Sm2SignVerify : public QWidget
{
    Q_OBJECT

public:
    explicit Sm2SignVerify(QWidget *parent = nullptr);
    ~Sm2SignVerify();

private slots:
    void on_pushButtonGenKey_clicked();

    void on_pushButtonSign_clicked();

    void on_pushButtonVerify_clicked();

private:
    Ui::Sm2SignVerify *ui;
};

#endif // SM2SIGNVERIFY_H
