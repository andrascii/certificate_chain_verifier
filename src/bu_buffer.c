/* by_buffer.c - copied and modified from crypto/x509/by_file.c */
/* Copyright (C) - should be the same as for OpenSSL
*/
#include "by_buffer.h"

#include <stdio.h>
#include <time.h>
#include <errno.h>

#include <openssl/lhash.h>
#include <openssl/buffer.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/ossl_typ.h>
#include <../crypto/x509/x509_lcl.h>

static int by_buffer_ctrl(X509_LOOKUP *ctx, int cmd, const char *argc,
	long argl, char **ret);

X509_LOOKUP_METHOD x509_buffer_lookup =
{
	"Load buffer into cache",
	NULL,        /* new */
	NULL,        /* free */
	NULL,         /* init */
	NULL,        /* shutdown */
	by_buffer_ctrl,    /* ctrl */
	NULL,        /* get_by_subject */
	NULL,        /* get_by_issuer_serial */
	NULL,        /* get_by_fingerprint */
	NULL,        /* get_by_alias */
};

X509_LOOKUP_METHOD *X509_LOOKUP_buffer(void)
{
	return(&x509_buffer_lookup);
}

static int by_buffer_ctrl(X509_LOOKUP *ctx, int cmd, const char *argp, long argl,
	char **ret)
{
	int ok = 0;
	char *certBuf;

	switch (cmd)
	{
	case X509_L_BUF_LOAD:
		if (argl == X509_FILETYPE_DEFAULT)
		{
			X509err(X509_F_BY_FILE_CTRL, X509_R_LOADING_DEFAULTS);
		}
		else
		{
			if (argl == X509_FILETYPE_PEM)
				ok = (X509_load_cert_crl_buf(ctx, argp,
					X509_FILETYPE_PEM) != 0);
			else
				ok = (X509_load_cert_buf(ctx, argp, (int)argl) != 0);
		}
		break;
	}
	return(ok);
}

int X509_load_cert_buf(X509_LOOKUP *ctx, const char *certBuf, int type)
{
	int ret = 0;
	BIO *in = NULL;
	int i, count = 0;
	X509 *x = NULL;

	if (certBuf == NULL) return(1);
	in = BIO_new(BIO_s_mem());
	if (in == NULL) goto err;

	if (type == X509_FILETYPE_PEM)
	{
		for (;;)
		{
			x = PEM_read_bio_X509_AUX(in, NULL, NULL, NULL);
			if (x == NULL)
			{
				if ((ERR_GET_REASON(ERR_peek_last_error()) ==
					PEM_R_NO_START_LINE) && (count > 0))
				{
					ERR_clear_error();
					break;
				}
				else
				{
					X509err(X509_F_X509_LOAD_CERT_FILE,
						ERR_R_PEM_LIB);
					goto err;
				}
			}
			i = X509_STORE_add_cert(ctx->store_ctx, x);
			if (!i) goto err;
			count++;
			X509_free(x);
			x = NULL;
		}
		ret = count;
	}
	else if (type == X509_FILETYPE_ASN1)
	{
		x = d2i_X509_bio(in, NULL);
		if (x == NULL)
		{
			X509err(X509_F_X509_LOAD_CERT_FILE, ERR_R_ASN1_LIB);
			goto err;
		}
		i = X509_STORE_add_cert(ctx->store_ctx, x);
		if (!i) goto err;
		ret = i;
	}
	else
	{
		X509err(X509_F_X509_LOAD_CERT_FILE, X509_R_BAD_X509_FILETYPE);
		goto err;
	}
err:
	if (x != NULL) X509_free(x);
	if (in != NULL) BIO_free(in);
	return(ret);
}

int X509_load_crl_buf(X509_LOOKUP *ctx, const char *certBuf, int type)
{
	int ret = 0;
	BIO *in = NULL;
	int i, count = 0;
	X509_CRL *x = NULL;

	if (certBuf == NULL) return(1);
	//in=BIO_new(BIO_s_file_internal());
	in = BIO_new(BIO_s_mem());

	if (in == NULL) goto err;

	if (type == X509_FILETYPE_PEM)
	{
		for (;;)
		{
			x = PEM_read_bio_X509_CRL(in, NULL, NULL, NULL);
			if (x == NULL)
			{
				if ((ERR_GET_REASON(ERR_peek_last_error()) ==
					PEM_R_NO_START_LINE) && (count > 0))
				{
					ERR_clear_error();
					break;
				}
				else
				{
					X509err(X509_F_X509_LOAD_CRL_FILE,
						ERR_R_PEM_LIB);
					goto err;
				}
			}
			i = X509_STORE_add_crl(ctx->store_ctx, x);
			if (!i) goto err;
			count++;
			X509_CRL_free(x);
			x = NULL;
		}
		ret = count;
	}
	else if (type == X509_FILETYPE_ASN1)
	{
		x = d2i_X509_CRL_bio(in, NULL);
		if (x == NULL)
		{
			X509err(X509_F_X509_LOAD_CRL_FILE, ERR_R_ASN1_LIB);
			goto err;
		}
		i = X509_STORE_add_crl(ctx->store_ctx, x);
		if (!i) goto err;
		ret = i;
	}
	else
	{
		X509err(X509_F_X509_LOAD_CRL_FILE, X509_R_BAD_X509_FILETYPE);
		goto err;
	}
err:
	if (x != NULL) X509_CRL_free(x);
	if (in != NULL) BIO_free(in);
	return(ret);
}

int X509_load_cert_crl_buf(X509_LOOKUP *ctx, const char *certBuf, int type)
{
	STACK_OF(X509_INFO) *inf;
	X509_INFO *itmp;
	BIO *in;
	int i, count = 0;
	if (type != X509_FILETYPE_PEM)
		return X509_load_cert_buf(ctx, certBuf, type);
	in = BIO_new(BIO_s_mem());
	if (!in)
	{
		X509err(X509_F_X509_LOAD_CERT_CRL_FILE, ERR_R_SYS_LIB);
		return 0;
	}
	BIO_write(in, certBuf, strlen(certBuf));
	inf = PEM_X509_INFO_read_bio(in, NULL, NULL, NULL);
	BIO_free(in);
	if (!inf)
	{
		X509err(X509_F_X509_LOAD_CERT_CRL_FILE, ERR_R_PEM_LIB);
		return 0;
	}
	for (i = 0; i < sk_X509_INFO_num(inf); i++)
	{
		itmp = sk_X509_INFO_value(inf, i);
		if (itmp->x509)
		{
			X509_STORE_add_cert(ctx->store_ctx, itmp->x509);
			count++;
		}
		if (itmp->crl)
		{
			X509_STORE_add_crl(ctx->store_ctx, itmp->crl);
			count++;
		}
	}
	sk_X509_INFO_pop_free(inf, X509_INFO_free);
	return count;
}