#include "certificate_pem_file_loader.h"
#include "finally.h"

namespace verifier
{

CertificatePemFileLoader::CertificatePemFileLoader(const std::string& path)
	: m_path(path)
{
}

X509Certificate CertificatePemFileLoader::load() const
{
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
		return nullptr;
	}

	if (BIO_read_filename(cert, m_path.data()) <= 0)
	{
		return nullptr;
	}

	return X509Certificate(PEM_read_bio_X509_AUX(cert, nullptr, nullptr, nullptr), [](X509* p) { if (p) X509_free(p); });
}

}