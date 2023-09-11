#ifndef RANDNUM_H
#define RANDNUM_H

#include "tserror.h"
#include <memory>
#include <openssl/rand.h>
#include <QIntValidator>
#include <QLineEdit>
#include <QString>
#include <QTextBrowser>
#include <QTextEdit>
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
