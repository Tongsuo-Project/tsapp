#include "sm2cert.h"
#include "ui_sm2cert.h"
#include <openssl/asn1.h>

Sm2Cert::Sm2Cert(QWidget *parent)
    : QWidget(parent)
    , ui(new Ui::Sm2Cert)
{
    ui->setupUi(this);
}

Sm2Cert::~Sm2Cert()
{
    delete ui;
}

static char *opt_getprog(void)
{
    return (char *) "";
}

/*
 * name is expected to be in the format /type0=value0/type1=value1/type2=...
 * where + can be used instead of / to form multi-valued RDNs if canmulti
 * and characters may be escaped by \
 */
static X509_NAME *parse_name(const char *cp, int chtype, int canmulti, const char *desc)
{
    int nextismulti = 0;
    char *work;
    X509_NAME *n;

    if (*cp++ != '/') {
        BIO_printf(bio_err,
                   "%s: %s name is expected to be in the format "
                   "/type0=value0/type1=value1/type2=... where characters may "
                   "be escaped by \\. This name is not in that format: '%s'\n",
                   opt_getprog(),
                   desc,
                   --cp);
        return NULL;
    }

    n = X509_NAME_new();
    if (n == NULL) {
        BIO_printf(bio_err, "%s: Out of memory\n", opt_getprog());
        return NULL;
    }
    work = OPENSSL_strdup(cp);
    if (work == NULL) {
        BIO_printf(bio_err, "%s: Error copying %s name input\n", opt_getprog(), desc);
        goto err;
    }

    while (*cp != '\0') {
        char *bp = work;
        char *typestr = bp;
        unsigned char *valstr;
        int nid;
        int ismulti = nextismulti;
        nextismulti = 0;

        /* Collect the type */
        while (*cp != '\0' && *cp != '=')
            *bp++ = *cp++;
        *bp++ = '\0';
        if (*cp == '\0') {
            BIO_printf(bio_err,
                       "%s: Missing '=' after RDN type string '%s' in %s name string\n",
                       opt_getprog(),
                       typestr,
                       desc);
            goto err;
        }
        ++cp;

        /* Collect the value. */
        valstr = (unsigned char *) bp;
        for (; *cp != '\0' && *cp != '/'; *bp++ = *cp++) {
            /* unescaped '+' symbol string signals further member of multiRDN */
            if (canmulti && *cp == '+') {
                nextismulti = 1;
                break;
            }
            if (*cp == '\\' && *++cp == '\0') {
                BIO_printf(bio_err,
                           "%s: Escape character at end of %s name string\n",
                           opt_getprog(),
                           desc);
                goto err;
            }
        }
        *bp++ = '\0';

        /* If not at EOS (must be + or /), move forward. */
        if (*cp != '\0')
            ++cp;

        /* Parse */
        nid = OBJ_txt2nid(typestr);
        if (nid == NID_undef) {
            BIO_printf(bio_err,
                       "%s: Skipping unknown %s name attribute \"%s\"\n",
                       opt_getprog(),
                       desc,
                       typestr);
            if (ismulti)
                BIO_printf(bio_err,
                           "Hint: a '+' in a value string needs be escaped using '\\' else a new "
                           "member of a multi-valued RDN is expected\n");
            continue;
        }
        if (*valstr == '\0') {
            BIO_printf(bio_err,
                       "%s: No value provided for %s name attribute \"%s\", skipped\n",
                       opt_getprog(),
                       desc,
                       typestr);
            continue;
        }
        if (!X509_NAME_add_entry_by_NID(
                n, nid, chtype, valstr, strlen((char *) valstr), -1, ismulti ? -1 : 0)) {
            ERR_print_errors(bio_err);
            BIO_printf(bio_err,
                       "%s: Error adding %s name attribute \"/%s=%s\"\n",
                       opt_getprog(),
                       desc,
                       typestr,
                       valstr);
            goto err;
        }
    }

    OPENSSL_free(work);
    return n;

err:
    X509_NAME_free(n);
    OPENSSL_free(work);
    return NULL;
}

static X509 *genCert(int type,
                     X509 *midCA,
                     EVP_PKEY *midcaPkey,
                     QString subj,
                     QString days,
                     char **key,
                     size_t *keylen)
{
    X509_NAME *name = NULL;
    X509 *userCer = NULL;
    std::string str;
    long len;
    BIO *out = NULL;
    X509_EXTENSION *cert_ex = NULL;
    X509_REQ *userReq = NULL;
    ASN1_INTEGER *aserial = NULL;
    const X509_NAME *rootCAname;
    time_t curTime;
    ASN1_TIME *rootBeforeTime = NULL;
    ASN1_TIME *rootAfterTime = NULL;
    EVP_PKEY *userKey = EVP_PKEY_Q_keygen(NULL, NULL, "SM2");

    if (userKey == NULL) {
        printTSError();
        return NULL;
    }

    out = BIO_new(BIO_s_mem());
    if (out == NULL)
        goto end;

    if (!PEM_write_bio_PrivateKey(out, userKey, NULL, NULL, 0, NULL, NULL)) {
        printTSError();
        goto end;
    }

    len = BIO_get_mem_data(out, NULL);
    if (len <= 0)
        goto end;

    *key = (char *) malloc(len);
    if (*key == NULL)
        goto end;

    if (BIO_read(out, *key, len) != len)
        goto end;

    *keylen = len;

    userReq = X509_REQ_new();
    if (userReq == NULL)
        goto end;

    X509_REQ_set_pubkey(userReq, userKey);

    if (!subj.isEmpty()) {
        name = parse_name(subj.toStdString().c_str(), MBSTRING_ASC, 1, "subject");

        if (!name) {
            return NULL;
        }

        X509_REQ_set_subject_name(userReq, name);
    }

    if (!X509_REQ_set_version(userReq, X509_VERSION_3)
        || !X509_REQ_sign(userReq, userKey, EVP_sm3()) || !X509_REQ_verify(userReq, userKey))
        goto end;

    if (type == 0) {
        str = "Key Encipherment, Data Encipherment";
    } else {
        str = "Digital Signature";
    }

    userCer = X509_new();
    if (userCer == NULL)
        goto end;

    cert_ex = X509V3_EXT_conf_nid(NULL, NULL, NID_key_usage, str.c_str());
    if (cert_ex == NULL)
        goto end;

    if (!X509_add_ext(userCer, cert_ex, -1) || !X509_set_version(userCer, X509_VERSION_3)
        || !X509_set_pubkey(userCer, userKey))
        goto end;

    aserial = ASN1_INTEGER_new();

    if (!ASN1_INTEGER_set(aserial, 0))
        goto end;

    if (!X509_set_serialNumber(userCer, aserial) || !X509_set_subject_name(userCer, name))
        goto end;

    rootCAname = X509_get_subject_name(midCA);
    if (!X509_set_issuer_name(userCer, rootCAname))
        goto end;

    curTime = time(NULL);
    rootBeforeTime = ASN1_TIME_new();
    rootAfterTime = ASN1_TIME_adj(NULL, curTime, 0, days.toInt() * 60 * 60 * 24);

    if (!ASN1_TIME_set(rootBeforeTime, curTime) || !X509_set_notBefore(userCer, rootBeforeTime)
        || !X509_set_notAfter(userCer, rootAfterTime))
        goto end;

    if (!X509_sign(userCer, midcaPkey, EVP_sm3()))
        goto end;

end:
    ASN1_TIME_free(rootAfterTime);
    ASN1_TIME_free(rootBeforeTime);
    ASN1_INTEGER_free(aserial);
    X509_EXTENSION_free(cert_ex);
    X509_REQ_free(userReq);
    BIO_free(out);
    EVP_PKEY_free(userKey);

    return userCer;
}

void Sm2Cert::on_pushButtonGen_clicked()
{
    QString subj = this->ui->lineEditSubj->text();
    QString days = this->ui->lineEditDays->text();
    QFile fsubca(":/certs/subca.pem");
    QFile fpkey(":/certs/subca.key");
    X509 *userSignCer = NULL, *userEncryptCer = NULL;
    char *signKey = NULL, *encKey = NULL;
    size_t signKeyLen, encKeyLen;
    QString subcaQstr, pkeyQstr;
    X509 *subca = NULL;
    EVP_PKEY *pkey = NULL;
    long len;
    char *buf = NULL;
    BIO *out = NULL;

    if (subj.isEmpty()) {
        QMessageBox::warning(NULL,
                             "warning",
                             QString("请输入主体名称！"),
                             QMessageBox::Close,
                             QMessageBox::Close);
        return;
    }

    if (days.isEmpty()) {
        QMessageBox::warning(NULL,
                             "warning",
                             QString("请输入有效期！"),
                             QMessageBox::Close,
                             QMessageBox::Close);
        return;
    }

    if (!fsubca.open(QIODevice::ReadOnly | QIODevice::Text)) {
        QMessageBox::warning(NULL,
                             "warning",
                             QString("subca.pem打开失败！"),
                             QMessageBox::Close,
                             QMessageBox::Close);
        return;
    }

    if (!fpkey.open(QIODevice::ReadOnly | QIODevice::Text)) {
        QMessageBox::warning(NULL,
                             "warning",
                             QString("subca.key打开失败！"),
                             QMessageBox::Close,
                             QMessageBox::Close);
        return;
    }
    QTextStream subcaInput(&fsubca);
    QTextStream pkeyInput(&fpkey);

    subcaQstr = subcaInput.readAll();
    pkeyQstr = pkeyInput.readAll();

    out = BIO_new(BIO_s_mem());
    if (out == NULL)
        goto end;

    if (BIO_write(out, subcaQstr.toStdString().c_str(), subcaQstr.size()) != subcaQstr.size())
        goto end;

    subca = PEM_read_bio_X509(out, NULL, NULL, NULL);
    if (subca == NULL) {
        this->ui->textBrowserSignKey->setText(subcaQstr);
        printTSError();
        goto end;
    }

    fsubca.close();
    BIO_reset(out);

    if (BIO_write(out, pkeyQstr.toStdString().c_str(), pkeyQstr.size()) != pkeyQstr.size())
        goto end;

    pkey = PEM_read_bio_PrivateKey(out, NULL, NULL, NULL);
    if (pkey == NULL) {
        printTSError();
        goto end;
    }

    fpkey.close();

    userSignCer = genCert(1, subca, pkey, subj, days, &signKey, &signKeyLen);
    if (userSignCer == NULL) {
        printTSError();
        goto end;
    }

    userEncryptCer = genCert(0, subca, pkey, subj, days, &encKey, &encKeyLen);
    if (userEncryptCer == NULL) {
        printTSError();
        goto end;
    }

    this->ui->textBrowserSignKey->setText(QString::fromStdString(std::string(signKey, signKeyLen)));
    this->ui->textBrowserEncryKey->setText(QString::fromStdString(std::string(encKey, encKeyLen)));

    BIO_reset(out);

    if (!PEM_write_bio_X509(out, userSignCer)) {
        printTSError();
        goto end;
    }

    len = BIO_get_mem_data(out, &buf);
    if (len <= 0)
        goto end;

    this->ui->textBrowserSignOutput->setPlainText(QString::fromStdString(std::string(buf, len)));

    BIO_reset(out);

    if (!PEM_write_bio_X509(out, userEncryptCer)) {
        printTSError();
        goto end;
    }

    len = BIO_get_mem_data(out, &buf);
    if (len <= 0)
        goto end;

    this->ui->textBrowserEncryptOutput->setPlainText(QString::fromStdString(std::string(buf, len)));

end:
    EVP_PKEY_free(pkey);
    X509_free(subca);
    BIO_free(out);
    free(signKey);
    free(encKey);
    X509_free(userSignCer);
    X509_free(userEncryptCer);
}
