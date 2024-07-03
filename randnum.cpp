#include "randnum.h"
#include "ui_randnum.h"

RandNum::RandNum(QWidget *parent)
    : QWidget(parent)
    , ui(new Ui::RandNum)
{
    ui->setupUi(this);
    /* 限制只能输入整数且范围为[1，128 * 1024]*/
    QIntValidator *aIntValidator = new QIntValidator;
    aIntValidator->setRange(1, 131072);
    ui->lineEditInput->setValidator(aIntValidator);
}

RandNum::~RandNum()
{
    delete ui;
}

void RandNum::on_pushButtonGen_clicked()
{
    QString inputByte = this->ui->lineEditInput->text();
    int randNumByte = inputByte.toInt();
    size_t len = randNumByte * 2 + 1;
    std::vector<unsigned char> buf;
    std::vector<char> str;

    buf.reserve(randNumByte);

    int ret = RAND_bytes((unsigned char *) buf.data(), randNumByte);

    if (ret == 0) {
        printTSError();
    } else {
        str.reserve(len);

        if (OPENSSL_buf2hexstr_ex(str.data(),
                                  len,
                                  NULL,
                                  (unsigned char *) buf.data(),
                                  randNumByte,
                                  '\0')
            != 1)
            return;

        this->ui->textBrowserOutput->setText(QString::fromStdString(std::string(str.data(), len)));
    }

    return;
}
