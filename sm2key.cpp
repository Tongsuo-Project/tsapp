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

void Sm2Key::on_pushButtonGen_clicked()
{
    /* 选定椭圆曲线组 */
    std::shared_ptr<EC_GROUP> group(EC_GROUP_new_by_curve_name(NID_sm2), EC_GROUP_free);
    if (!group) {
        getError();
        return;
    }
    /* 密钥上下文生成 */
    std::shared_ptr<EC_KEY> key(EC_KEY_new(), EC_KEY_free);
    /* 设定密钥的曲线组 */
    EC_KEY_set_group(key.get(), group.get());
    /* 生成EC_KEY */
    int res = EC_KEY_generate_key(key.get());
    if (res != 1) {
        getError();
        return;
    }
    /* 取公钥并转换为十六进制字符串 */
    const EC_POINT *pubPoint = EC_KEY_get0_public_key(key.get());
    std::shared_ptr<char> pubHexStr(EC_POINT_point2hex(group.get(),
                                                       pubPoint,
                                                       POINT_CONVERSION_UNCOMPRESSED,
                                                       NULL),
                                    [](char *pub) { OPENSSL_free(pub); });
    /* 取私钥并转换为十六进制字符串 */
    const BIGNUM *priBn = EC_KEY_get0_private_key(key.get());
    std::shared_ptr<char> priHexStr(BN_bn2hex(priBn), [](char *pri) { OPENSSL_free(pri); });
    /* 在浏览框中显示公钥和私钥 */
    this->ui->textBrowserPrikey->setText(QString(priHexStr.get()));
    this->ui->textBrowserPubkey->setText(QString(pubHexStr.get()));
}
