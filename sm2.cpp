#include <sm2.h>
#include <vector>

EVP_PKEY *sm2_key_new_from_raw_pub(const std::string &pub)
{
    std::string hex;
    std::vector<unsigned char> buf;
    OSSL_PARAM_BLD *keybld = NULL;
    OSSL_PARAM *keyparams = NULL;
    EVP_PKEY_CTX *keyctx = NULL;
    EVP_PKEY *pkey = NULL;

    hex = std::string("04") + pub;

    keybld = OSSL_PARAM_BLD_new();
    if (keybld == NULL)
        goto end;

    buf.reserve(hex.length() / 2);

    if (OPENSSL_hexstr2buf_ex(buf.data(), buf.capacity(), NULL, hex.c_str(), '\0') != 1)
        goto end;

    if (!OSSL_PARAM_BLD_push_utf8_string(keybld, OSSL_PKEY_PARAM_GROUP_NAME, "SM2", 3))
        goto end;

    if (!OSSL_PARAM_BLD_push_octet_string(keybld,
                                          OSSL_PKEY_PARAM_PUB_KEY,
                                          buf.data(),
                                          buf.capacity()))
        goto end;

    keyparams = OSSL_PARAM_BLD_to_param(keybld);
    keyctx = EVP_PKEY_CTX_new_from_name(NULL, "SM2", NULL);

    if (keyctx == NULL || keyparams == NULL)
        goto end;

    if (EVP_PKEY_fromdata_init(keyctx) <= 0
        || EVP_PKEY_fromdata(keyctx, &pkey, EVP_PKEY_PUBLIC_KEY, keyparams) <= 0)
        goto end;
end:
    EVP_PKEY_CTX_free(keyctx);
    OSSL_PARAM_free(keyparams);
    OSSL_PARAM_BLD_free(keybld);
    return pkey;
}

EVP_PKEY *sm2_key_new_from_raw_pub_and_priv(const std::string &pub, const std::string &priv)
{
    std::string hex;
    std::vector<unsigned char> buf;
    OSSL_PARAM_BLD *keybld = NULL;
    OSSL_PARAM *keyparams = NULL;
    EVP_PKEY_CTX *keyctx = NULL;
    EVP_PKEY *pkey = NULL;
    BIGNUM *bn = NULL;

    keybld = OSSL_PARAM_BLD_new();
    if (keybld == NULL)
        goto end;

    if (!OSSL_PARAM_BLD_push_utf8_string(keybld, OSSL_PKEY_PARAM_GROUP_NAME, "SM2", 3))
        goto end;

    buf.clear();
    buf.reserve(priv.length() / 2);

    if (OPENSSL_hexstr2buf_ex(buf.data(), buf.capacity(), NULL, priv.c_str(), '\0') != 1)
        goto end;

    bn = BN_new();
    if (bn == NULL)
        goto end;

    if (BN_bin2bn(buf.data(), buf.capacity(), bn) == NULL
        || !OSSL_PARAM_BLD_push_BN(keybld, OSSL_PKEY_PARAM_PRIV_KEY, bn))
        goto end;

    hex = std::string("04") + pub;

    buf.clear();
    buf.reserve(hex.length() / 2);

    if (OPENSSL_hexstr2buf_ex(buf.data(), buf.capacity(), NULL, hex.c_str(), '\0') != 1)
        goto end;

    if (!OSSL_PARAM_BLD_push_octet_string(keybld,
                                          OSSL_PKEY_PARAM_PUB_KEY,
                                          buf.data(),
                                          buf.capacity()))
        goto end;

    keyparams = OSSL_PARAM_BLD_to_param(keybld);
    keyctx = EVP_PKEY_CTX_new_from_name(NULL, "SM2", NULL);

    if (keyctx == NULL || keyparams == NULL)
        goto end;

    if (EVP_PKEY_fromdata_init(keyctx) <= 0
        || EVP_PKEY_fromdata(keyctx, &pkey, EVP_PKEY_KEYPAIR, keyparams) <= 0)
        goto end;
end:
    BN_free(bn);
    EVP_PKEY_CTX_free(keyctx);
    OSSL_PARAM_free(keyparams);
    OSSL_PARAM_BLD_free(keybld);
    return pkey;
}

int sm2_key_get_priv_pem(const EVP_PKEY *pkey, std::string &pem)
{
    int ret = 0;
    BIO *out = NULL;
    long len;
    char *buf = NULL;

    out = BIO_new(BIO_s_mem());
    if (out == NULL)
        goto end;

    if (!PEM_write_bio_PrivateKey(out, pkey, NULL, NULL, 0, NULL, NULL))
        goto end;

    len = BIO_get_mem_data(out, &buf);

    pem = std::string(buf, len);

    ret = 1;
end:
    BIO_free(out);
    return ret;
}

int sm2_key_get_pub_pem(const EVP_PKEY *pkey, std::string &pem)
{
    int ret = 0;
    BIO *out = NULL;
    long len;
    char *buf = NULL;

    out = BIO_new(BIO_s_mem());
    if (out == NULL)
        goto end;

    if (!PEM_write_bio_PUBKEY(out, pkey))
        goto end;

    len = BIO_get_mem_data(out, &buf);

    pem = std::string(buf, len);

    ret = 1;
end:
    BIO_free(out);
    return ret;
}

int sm2_key_get_pub_hex(const EVP_PKEY *pkey, std::string &hex)
{
    BIGNUM *qx = NULL, *qy = NULL;
    char *pubx = NULL, *puby = NULL;

    if (!EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_EC_PUB_X, &qx)
        || !EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_EC_PUB_Y, &qy))
        return 0;

    pubx = BN_bn2hex(qx);
    puby = BN_bn2hex(qy);

    hex = std::string(pubx) + std::string(puby);

    BN_clear_free(qx);
    BN_clear_free(qy);
    OPENSSL_free(pubx);
    OPENSSL_free(puby);

    return 1;
}

int sm2_key_get_priv_hex(const EVP_PKEY *pkey, std::string &hex)
{
    BIGNUM *priv = NULL;
    char *buf = NULL;

    if (!EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY, &priv))
        return 0;

    buf = BN_bn2hex(priv);

    hex = std::string(buf);

    OPENSSL_free(buf);
    BN_clear_free(priv);

    return 1;
}
