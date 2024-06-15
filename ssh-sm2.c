/*
    This code is used for substitude the rsa algorithm. We choose sm2.
    利用sm2国密算法对ssh中的公钥密码进行更换，实现公钥改造
    这个文件用于与Openssl对接，将Openssl的国密算法参数导入到这里进行认证。后面要实现的话要先在
	openbsd文件夹里添加sm3作为哈希函数。
	目前计划是将openssh包里面的所有有关rsa的函数统一替换成sm2，然后去openssl里面找调用的函数和参数有没有差
	有差就改
*/

/*
	这个包现在又个问题
*/
#include "includes.h"

/*
	下面这个宏表示在这下面的所有函数在没有openssl的时候是不编译的，vscode里面编辑嫌麻烦
	可以在最后一行#endif给注释掉
*/



//#if defined(WITH_OPENSSL) && defined(OPENSSL_HAS_ECC)

#include <sys/types.h>
/*
	它这个包整个就是引用openssl/ec.h
*/
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/sm2.h>
#include <openssl/evp.h>
#include <openssl/sm2.h>

#include <string.h>

#include "sshbuf.h"
#include "ssherr.h"
#include "digest.h"
#define SSHKEY_INTERNAL
#include "sshkey.h"

#include "openbsd-compat/openssl-compat.h"

/*
	此处使用的参数跟调用了ECDSA_SIG,这边openssl并没有导入ECDSA_SIG，
	但是实际上SM系列的函数也可以算是ECDSA算法大类的一个部分
	所以为了方便起见，我在这边直接借用ECDSA的参数
*/


/* ARGSUSED */
int
ssh_sm2_sign(const struct sshkey *key, u_char **sigp, size_t *lenp,
    const u_char *data, size_t datalen, u_int compat)
{
	ECDSA_SIG *sig = NULL;
	int hash_alg;

	if (lenp != NULL)
		*lenp = 0;
	if (sigp != NULL)
		*sigp = NULL;

	if (key == NULL || key->sm2 == NULL ||
	    sshkey_type_plain(key->type) != KEY_SM2)
		return SSH_ERR_INVALID_ARGUMENT;
	
	/* 获取 SM2 密钥 */
	EC_KEY *ec_key = EC_KEY_new_by_curve_name(NID_sm2);
    if (ec_key == NULL) {
        return SSH_ERR_INTERNAL_ERROR;
    }

	/* 使用 SM2 密钥对数据进行签名 */
	ECDSA_SIG *signature = ossl_sm2_do_sign(ec_key, EVP_sm3(), NULL, 0, data, datalen);
    if (signature == NULL) {
        EC_KEY_free(ec_key);
        return SSH_ERR_INTERNAL_ERROR;
    }

	/* 将签名转换为 DER 编码的格式 */
	int derlen = i2d_ECDSA_SIG(signature, NULL);
    if (derlen <= 0) {
        EC_KEY_free(ec_key);
        ECDSA_SIG_free(signature);
        return SSH_ERR_INTERNAL_ERROR;
    }

	*sigp = malloc(derlen);
    if (*sigp == NULL) {
        EC_KEY_free(ec_key);
        ECDSA_SIG_free(signature);
        return SSH_ERR_ALLOC_FAIL;
    }

    *lenp = derlen;
    unsigned char *p = *sigp;
    i2d_ECDSA_SIG(signature, &p);

    EC_KEY_free(ec_key);
    ECDSA_SIG_free(signature);

    return 0;
}

/* ARGSUSED */
int
ssh_sm2_verify(const struct sshkey *key,
    const u_char *signature, size_t signaturelen,
    const u_char *data, size_t datalen, u_int compat)
{
	ECDSA_SIG *sig = NULL;
	char *ktype = NULL;

	if (key == NULL || key->sm2 == NULL ||
	    sshkey_type_plain(key->type) != KEY_SM2 ||
	    signature == NULL || signaturelen == 0)
		return SSH_ERR_INVALID_ARGUMENT;

	/* 获取 SM2 密钥 */
    EC_KEY *ec_key = EC_KEY_new_by_curve_name(NID_sm2);
    if (ec_key == NULL) {
        return SSH_ERR_INTERNAL_ERROR;
    }

	/* 从 DER 编码的签名中提取 ECDSA_SIG 结构 */
    const unsigned char *p = signature;
    ECDSA_SIG *sig = d2i_ECDSA_SIG(NULL, &p, signaturelen);
    if (sig == NULL) {
        EC_KEY_free(ec_key);
        return SSH_ERR_INTERNAL_ERROR;
    }

    /* 使用 SM2 密钥验证签名 */
    int ret = ossl_sm2_do_verify(data, datalen, signature, signaturelen, ec_key);

    EC_KEY_free(ec_key);
    ECDSA_SIG_free(sig);

    return ret == 1 ? 0 : SSH_ERR_SIGNATURE_INVALID;
}

//#endif /* WITH_OPENSSL && OPENSSL_HAS_ECC */
