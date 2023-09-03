#include "sm2key.h"
#include "ui_sm2key.h"

Sm2Key::Sm2Key(QWidget *parent)
    : QWidget(parent)
    , ui(new Ui::Sm2Key)
{
    ui->setupUi(this);
}

Sm2Key::~Sm2Key()
{
    delete ui;
}

EC_KEY *Sm2Key::genSm2Key()
{
    /* 选定椭圆曲线组 */
    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_sm2);
    if (!group) {
        return NULL;
    }
    /* 密钥上下文生成 */
    EC_KEY *key = EC_KEY_new();
    /* 设定密钥的曲线组 */
    EC_KEY_set_group(key, group);
    /* 生成EC_KEY */
    int res = EC_KEY_generate_key(key);
    if (res != 1) {
        return NULL;
    }
    /* 检查密钥 */
    res = EC_KEY_check_key(key);
    if (res != 1) {
        EC_KEY_free(key);
        return NULL;
    }
    /* 释放内存资源 */
    EC_GROUP_free(group);
    return key;
}

void Sm2Key::on_pushButtonGen_clicked()
{
    /* 生成EC_KEY和对应的group */
    EC_KEY *key = this->genSm2Key();
    const EC_GROUP *group = EC_KEY_get0_group(key);
    /* 取公钥并转换为十六进制字符串 */
    const EC_POINT *pubPoint = EC_KEY_get0_public_key(key);
    char *pubHexStr = EC_POINT_point2hex(group, pubPoint, POINT_CONVERSION_UNCOMPRESSED, NULL);
    /* 取私钥并转换为十六进制字符串 */
    const BIGNUM *priBn = EC_KEY_get0_private_key(key);
    char *priHexStr = BN_bn2hex(priBn);
    /* 在浏览框中显示公钥和私钥 */
    this->ui->textBrowserPrikey->setText(QString(priHexStr));
    this->ui->textBrowserPubkey->setText(QString(pubHexStr));
    /* 释放内存资源 */
    OPENSSL_free(priHexStr);
    OPENSSL_free(pubHexStr);
    EC_KEY_free(key);
}
