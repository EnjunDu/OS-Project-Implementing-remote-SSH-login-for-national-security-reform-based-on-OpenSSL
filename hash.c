/* $OpenBSD: hash.c,v 1.6 2019/11/29 00:11:21 djm Exp $ */
/*
 * Public domain. Author: Christian Weisgerber <naddy@openbsd.org>
 * API compatible reimplementation of function from nacl
 */

/*
	此处好像是管理哈希的函数，如果有openssl的话就将这一块添加sm3算法，
*/

#include "includes.h"

#include "crypto_api.h"

#include <stdarg.h>

#ifdef WITH_OPENSSL
#include <openssl/evp.h>

int
crypto_hash_sha512(unsigned char *out, const unsigned char *in,
    unsigned long long inlen)
{

	if (!EVP_Digest(in, inlen, out, NULL, EVP_sha512(), NULL))
		return -1;
	return 0;
}

int crypto_hash_sm3(unsigned char *out, const unsigned char *in,
	unsigned long long inlen)
	{
		if(!EVP_Digest(in, inlen, out, NULL, EVP_sm3(), NULL))
			return -1;
		return 0;
	}

#else
# ifdef HAVE_SHA2_H
#  include <sha2.h>
# endif

/*
	这个宏定义下的HAVE_SM3_H不知条件在那得看看啥情况
*/

#ifdef HAVE_SM3_H
#include <sm3.h>
#endif

int
crypto_hash_sha512(unsigned char *out, const unsigned char *in,
    unsigned long long inlen)
{

	SHA2_CTX ctx;

	SHA512Init(&ctx);
	SHA512Update(&ctx, in, inlen);
	SHA512Final(out, &ctx);

	return 0;
}

/*
	此处添加的函数对应的文件在/openbsd-compat/sm3.h里面，现在sm3.h还没改好，要从sha2.h那边对应拔下来
	如果有办法实现同样的目的就不用了

	目前我直接把sm3的代码扔进去了，到时候测试的时候如果不能用再去openssl找
*/

int crypto_hash_sm3(unsigned char *out, const unsigned char *in,
    unsigned long long inlen)
{
	SM3_CTX ctx;

	SM3Init(&ctx);
	SM3Update(&ctx, in, inlen);
	SM3Final(out, &ctx);

	return 0;
}
#endif /* WITH_OPENSSL */
