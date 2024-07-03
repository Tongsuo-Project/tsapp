#ifndef TSERROR_H
#define TSERROR_H
#include <openssl/err.h>
#include <QMessageBox>

/* 错误处理函数 */
void getError();
void printTSError();

extern BIO *bio_err;

#endif // TSERROR_H
