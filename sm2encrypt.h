#ifndef SM2ENCRYPT_H
#define SM2ENCRYPT_H

#include <QWidget>

namespace Ui {
class Sm2Encrypt;
}

class Sm2Encrypt : public QWidget
{
    Q_OBJECT

public:
    explicit Sm2Encrypt(QWidget *parent = nullptr);
    ~Sm2Encrypt();

private:
    Ui::Sm2Encrypt *ui;
};

#endif // SM2ENCRYPT_H
