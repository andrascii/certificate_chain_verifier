#include "finally.h"
#include "verifier.h"
#include "certificate_pem_file_loader.h"

int main()
{
	using namespace verifier;

	OPENSSL_init_ssl(OPENSSL_INIT_LOAD_CONFIG, NULL);

	// Root certificate. It will not be verified.
	const std::string rootCertificatePath("C:\\Users\\a.pugachev\\Desktop\\certchain\\ca_gost_2012.crt");

	// Path to the intermediate certificate
	const std::string caCertificatePath("C:\\Users\\a.pugachev\\Desktop\\certchain\\slave_ca_gost_2012.crt");

	// Certificate to verify
	const std::string endCertificatePath("C:\\Users\\a.pugachev\\Desktop\\certchain\\user.cer");

	const std::shared_ptr<ICertificateLoader> loader = std::make_shared<CertificatePemFileLoader>(caCertificatePath);

	// Intermediate certificates which also must be verified.
	// It also used to pass verification from end certificate up to the root certificate.
	X509CertificateChain untrustedCertificateChain;
	untrustedCertificateChain.addCertificate(loader->load());

	const Verifier verifyObject(
		std::make_shared<CertificatePemFileLoader>(rootCertificatePath),
		std::make_shared<CertificatePemFileLoader>(endCertificatePath),
		untrustedCertificateChain);

	const std::pair<bool, std::string> result = verifyObject.verify();

	if (result.first)
	{
		std::cout << "Certificate chain successfully verified: " << result.second << std::endl;
	}
	else
	{
		std::cout << "Certificate chain failed verification: " << result.second << std::endl;
	}

	std::cin.get();
}