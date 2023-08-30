#include "home.h"
#include "ui_home.h"
#include <QPainter>

Home::Home(QWidget *parent)
    : QWidget(parent)
    , ui(new Ui::Home)
{
    ui->setupUi(this);
}

Home::~Home()
{
    delete ui;
}

void Home::paintEvent(QPaintEvent *event)
{
    //重写自动执行
    QPixmap pixmap = QPixmap("://images/HomeBackground.png")
                         .scaled(this->size(), Qt::IgnoreAspectRatio, Qt::SmoothTransformation);
    QPainter painter(this);
    painter.drawPixmap(this->rect(), pixmap); //画家画图片
}
