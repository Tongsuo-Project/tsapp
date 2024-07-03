#include "about.h"
#include "ui_about.h"
#include "version.h"

About::About(QWidget *parent)
    : QDialog(parent)
    , ui(new Ui::About)
{
    ui->setupUi(this);

    QString text = ui->textBrowser->toHtml();

    text.replace("|version|", version);

    ui->textBrowser->setHtml(text);
}

About::~About()
{
    delete ui;
}

void About::on_pushButton_clicked()
{
    this->close();
}
