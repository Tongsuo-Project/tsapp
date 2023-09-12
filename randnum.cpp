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
    std::unique_ptr<unsigned char> buf(new unsigned char[randNumByte]);
    /* 获取随机数输出栏 */
    QTextBrowser *outputNum = this->ui->textBrowserOutput;
    /* 调用随机数生成函数 */
    int ret = RAND_bytes(buf.get(), randNumByte);
    if (ret == 0) {
        /* 生成失败弹窗 */
        getError();
        return;
    } else {
        /* 生成成功将结果写到输出框 */
        std::shared_ptr<char> outBuf(OPENSSL_buf2hexstr(buf.get(), randNumByte),
                                     [](char *outbuf) { OPENSSL_free(outbuf); });
        outputNum->setText(QString(outBuf.get()));
    }
}
