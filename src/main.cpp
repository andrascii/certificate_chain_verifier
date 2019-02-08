#include <iostream>
#include <boost/asio.hpp>
#include <openssl/lhash.h>
#include <openssl/buffer.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/ossl_typ.h>
#include "finally.h"

static int check(X509_STORE* ctx, const char* certBuf);
static X509* certificateFromPemFile(const char* certBuf);
int verify(const char* certfile, const char* CAfile);

int main()
{
	verify("C:\\Users\\a.pugachev\\Desktop\\edvards.cer", "C:\\Users\\a.pugachev\\Desktop\\id256_A_CA.cer");

	std::cout << "test\n";
}

int verify(const char* certfile, const char* CAfile)
{
	int result = 0;
	X509_STORE* certContext = nullptr;
	X509_LOOKUP* lookup = nullptr;

	certContext = X509_STORE_new();

	Finally finallyObject([&certContext]
	{
		if (certContext)
		{
			X509_STORE_free(certContext);
		}
	});

	if (!certContext)
	{
		return result;
	}

	OpenSSL_add_all_algorithms();

	lookup = X509_STORE_add_lookup(certContext, X509_LOOKUP_file());

	if (!lookup || !X509_LOOKUP_load_file(lookup, CAfile, X509_FILETYPE_PEM))
	{
		return result;
	}

	lookup = X509_STORE_add_lookup(certContext, X509_LOOKUP_hash_dir());

	if (!lookup)
	{
		return result;
	}

	X509_LOOKUP_add_dir(lookup, nullptr, X509_FILETYPE_DEFAULT);

	result = check(certContext, certfile);

	return result;
}

static X509* certificateFromPemFile(const char* path)
{
	X509* x = nullptr;
	BIO* cert;

	Finally finallyObject([&cert]
	{
		if (cert)
		{
			BIO_free(cert);
		}
	});

	if ((cert = BIO_new(BIO_s_file())) == nullptr)
	{
		return x;
	}

	if (BIO_read_filename(cert, path) <= 0)
	{
		return x;
	}

	x = PEM_read_bio_X509_AUX(cert, nullptr, nullptr, nullptr);

	return x;
}

static int check(X509_STORE* ctx, const char* file)
{
	X509 *x = NULL;
	int i = 0, ret = 0;
	X509_STORE_CTX *csc;

	x = certificateFromPemFile(file);
	if (x == NULL)
		goto end;

	csc = X509_STORE_CTX_new();
	if (csc == NULL)
		goto end;
	X509_STORE_set_flags(ctx, 0);
	if (!X509_STORE_CTX_init(csc, ctx, x, 0))
		goto end;
	i = X509_verify_cert(csc);
	X509_STORE_CTX_free(csc);

	ret = 0;
end:
	ret = (i > 0);
	if (x != NULL)
		X509_free(x);

	return(ret);
}