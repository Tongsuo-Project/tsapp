#include "randnum.h"
#include "ui_randnum.h"

RandNum::RandNum(QWidget *parent)
    : QWidget(parent)
    , ui(new Ui::RandNum)
{
    ui->setupUi(this);
    /* 限制只能输入整数且范围为[1，256]*/
    QIntValidator *aIntValidator = new QIntValidator;
    aIntValidator->setRange(1, 256);
    ui->lineEditInput->setValidator(aIntValidator);
}

RandNum::~RandNum()
{
    delete ui;
}

void RandNum::on_pushButtonGen_clicked()
{
    /* 获取用户输入 */
    QString inputByte = this->ui->lineEditInput->text();
    int randNumByte = inputByte.toInt();
    unsigned char *buf = new unsigned char[randNumByte];
    /* 获取随机数输出栏 */
    QTextBrowser *outputNum = this->ui->textBrowserOutput;
    /* 调用Tongsuo中的随机数生成函数 */
    int ret = RAND_bytes(buf, randNumByte);
    if (ret == 0) {
        return;
    } else {
        char *outBuf = OPENSSL_buf2hexstr(buf, randNumByte);
        outputNum->setText(QString(outBuf));
    }
    /* 释放内存 */
    delete[] buf;
}
