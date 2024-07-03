#ifndef SM2_H
#define SM2_H

#include <openssl/bio.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/params.h>
#include <openssl/pem.h>
#include <string>

int sm2_key_get_pub_pem(const EVP_PKEY *pkey, std::string &pem);
int sm2_key_get_priv_pem(const EVP_PKEY *pkey, std::string &pem);
int sm2_key_get_pub_hex(const EVP_PKEY *pkey, std::string &hex);
int sm2_key_get_priv_hex(const EVP_PKEY *pkey, std::string &hex);
EVP_PKEY *sm2_key_new_from_raw_pub(const std::string &pub);
EVP_PKEY *sm2_key_new_from_raw_pub_and_priv(const std::string &pub, const std::string &priv);

#endif // SM2_H
