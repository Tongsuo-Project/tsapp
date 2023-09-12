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
    /* 获取用户输入 */
    QString input = this->ui->plainTextEditInput->toPlainText();
    /* 进行哈希生成摘要 */
    unsigned char md[32] = {};
    size_t mdlen = 0;
    if (!EVP_Q_digest(NULL, "SM3", NULL, input.toStdString().c_str(), input.size(), md, &mdlen)) {
        /* 错误处理 */
        getError();
        return;
    }
    /* 转为16进制字符串并输出 */
    std::shared_ptr<char> output(OPENSSL_buf2hexstr(md, mdlen),
                                 [](char *buf) { OPENSSL_free(buf); });
    this->ui->textBrowserOutput->setText(QString(output.get()));
}
