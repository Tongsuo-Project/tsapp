#include "sm3hash.h"
#include "ui_sm3hash.h"

Sm3Hash::Sm3Hash(QWidget *parent)
    : QWidget(parent)
    , ui(new Ui::Sm3Hash)
{
    ui->setupUi(this);
}

Sm3Hash::~Sm3Hash()
{
    delete ui;
}

void Sm3Hash::on_pushButtonGen_clicked()
{
    QString input = this->ui->plainTextEditInput->toPlainText();
    unsigned char md[32] = {};
    unsigned char hex[65];
    size_t mdlen = 0;

    if (input.isEmpty()) {
        if (input.isEmpty()) {
            QMessageBox::warning(NULL,
                                 "warning",
                                 QString("请输入数据！"),
                                 QMessageBox::Close,
                                 QMessageBox::Close);
            return;
        }
    }

    if (!EVP_Q_digest(NULL, "SM3", NULL, input.toStdString().c_str(), input.size(), md, &mdlen)) {
        printTSError();
        return;
    }

    if (OPENSSL_buf2hexstr_ex((char *) hex, sizeof(hex), NULL, md, mdlen, '\0') != 1) {
        printTSError();
        return;
    }

    this->ui->textBrowserOutput->setText(
        QString::fromStdString(std::string((char *) hex, sizeof(hex))));
}
