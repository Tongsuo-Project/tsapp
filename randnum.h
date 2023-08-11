#ifndef RANDNUM_H
#define RANDNUM_H

#include <QWidget>

namespace Ui {
class RandNum;
}

class RandNum : public QWidget
{
    Q_OBJECT

public:
    explicit RandNum(QWidget *parent = nullptr);
    ~RandNum();

private slots:
    void on_pushButtonGen_clicked();

private:
    Ui::RandNum *ui;
};

#endif // RANDNUM_H
