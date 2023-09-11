#include "tserror.h"

void getError()
{
    unsigned long er = 0;
    char erbuf[512] = {0};
    size_t erlen = 512;
    /* 获取错误号 */
    er = ERR_get_error();
    /* 将错误号转变为对应字符串 */
    ERR_error_string_n(er, erbuf, erlen);
    /* 弹窗显示 */
    QMessageBox::warning(NULL,
                         "warning",
                         QString::asprintf("%s", erbuf),
                         QMessageBox::Close,
                         QMessageBox::Close);
    return;
}
