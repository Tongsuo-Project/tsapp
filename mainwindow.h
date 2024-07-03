#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include "about.h"
#include <QMainWindow>

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void on_action_about_triggered();

    void on_action_exit_triggered();

    void on_listWidget_currentRowChanged(int currentRow);

private:
    Ui::MainWindow *ui;

    About *about;
};

#endif // MAINWINDOW_H
