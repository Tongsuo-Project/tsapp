#include "mainwindow.h"
#include <openssl/ssl.h>
#include <QApplication>

BIO *bio_err = NULL;

int main(int argc, char *argv[])
{
    if (!OPENSSL_init_ssl(OPENSSL_INIT_NO_LOAD_CONFIG, NULL))
        return 1;

    bio_err = BIO_new_fp(stderr, BIO_NOCLOSE | BIO_FP_TEXT);

    QApplication a(argc, argv);
    MainWindow w;
    w.show();
    return a.exec();
}
