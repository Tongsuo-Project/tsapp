#ifndef SM3HASH_H
#define SM3HASH_H

#include "tserror.h"
#include <memory>
#include <openssl/evp.h>
#include <QWidget>

namespace Ui {
class Sm3Hash;
}

class Sm3Hash : public QWidget
{
    Q_OBJECT

public:
    explicit Sm3Hash(QWidget *parent = nullptr);
    ~Sm3Hash();

private slots:
    void on_pushButtonGen_clicked();

private:
    Ui::Sm3Hash *ui;
};

#endif // SM3HASH_H
