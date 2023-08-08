#include "randnum.h"
#include "ui_randnum.h"
#include <QLineEdit>
#include <QTextEdit>
#include <QString>
#include <QTextBrowser>
#include <openssl/rand.h>
#include <QIntValidator>
RandNum::RandNum(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::RandNum)
{
    ui->setupUi(this);
    QIntValidator *aIntValidator = new QIntValidator;
    aIntValidator->setRange(0, 65535);
    ui->lineEditMin->setValidator(aIntValidator);
    ui->lineEditMax->setValidator(aIntValidator);

}

RandNum::~RandNum()
{
    delete ui;
}




void RandNum::on_pushBtnGemRand_clicked()
{
    /* 获取用户输入的随机数范围 */
    QString minNum = this->ui->lineEditMin->text();
    QString maxNum = this->ui->lineEditMax->text();

    /* 获取输出栏 */
    QTextBrowser *outputNum = this->ui->textBrowserShowNum;

    unsigned char buf[2] = {0};
    int ret = -1;
    int res = -1;

    if (minNum.toInt() >= maxNum.toInt()) {
        outputNum->setText(QString("无效的范围值！请重试"));
        return;
    }


    while (res < minNum.toInt() || res > maxNum.toInt()) {
        ret = RAND_bytes(buf, sizeof(buf));
        if (ret == 0 ) {
            outputNum->setText(QString("生成失败请重试！"));
            break;
        }
        if (maxNum.toInt() < 255) {
            res = int(buf[0]);
        }
        else {
            QString highBit = QString::number(int(buf[1]), 2);
            QString lowBit = QString::number(int(buf[0]), 2);
            QString resBit = highBit + lowBit;
            bool ok;
            res = resBit.toInt(&ok,2);
            resBit = QString::number(res, 10);
            res = resBit.toInt();
        }
    }
    outputNum->setText(QString::number(res));

}

