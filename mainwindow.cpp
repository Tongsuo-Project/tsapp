#include "mainwindow.h"
#include "ui_mainwindow.h"

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    about = new About();
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::on_action_about_triggered()
{
    about->show();
}

void MainWindow::on_action_exit_triggered()
{
    this->close();
}

void MainWindow::on_listWidget_currentRowChanged(int currentRow)
{
    this->ui->stackedWidget->setCurrentIndex(currentRow);
}
