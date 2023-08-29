#include "randnum.h"
#include "ui_randnum.h"
#include <openssl/rand.h>
#include <QIntValidator>
#include <QLineEdit>
#include <QString>
#include <QTextBrowser>
#include <QTextEdit>

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
    int ret = RAND_bytes(buf, sizeof(buf));
    if (ret == 0) {
        outputNum->setText(QString("生成失败请重试！"));
    } else {
        QString res = QString::asprintf("%02X ", buf[0]);
        for (int i = 1; i < randNumByte; ++i) {
            res += QString::asprintf("%02X ", buf[i]);
        }
        outputNum->setText(res);
    }

    delete[] buf;
}
