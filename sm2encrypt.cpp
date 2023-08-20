#include "sm2encrypt.h"
#include "ui_sm2encrypt.h"

Sm2Encrypt::Sm2Encrypt(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::Sm2Encrypt)
{
    ui->setupUi(this);
}

Sm2Encrypt::~Sm2Encrypt()
{
    delete ui;
}
