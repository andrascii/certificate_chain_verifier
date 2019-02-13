#include "finally.h"
#include "verifier.h"
#include "certificate_pem_file_loader.h"
#include "certificate_asn1_file_loader.h"

int main()
{
	using namespace verifier;

	OPENSSL_init_ssl(OPENSSL_INIT_LOAD_CONFIG, NULL);

	// Root certificate. It will not be verified.
	const std::string rootCertificatePath("C:\\Users\\a.pugachev\\Desktop\\certchain\\ca_gost_2012.cer");

	// Path to the intermediate certificate
	const std::string caCertificatePath("C:\\Users\\a.pugachev\\Desktop\\certchain\\slave_ca_gost_2012.cer");

	// Certificate to verify
	const std::string verifyingCertificatePath("C:\\Users\\a.pugachev\\Desktop\\certchain\\user.cer");

	const std::shared_ptr<ICertificateLoader> caCertificateLoader = std::make_shared<CertificateAsn1FileLoader>(caCertificatePath);
	const std::shared_ptr<ICertificateLoader> rootCertificateLoader = std::make_shared<CertificateAsn1FileLoader>(rootCertificatePath);

	// Intermediate certificates which also must be verified.
	// It also used to pass verification from end certificate up to the root certificate.
	X509CertificateChain untrustedCertificateChain;
	untrustedCertificateChain.addCertificate(caCertificateLoader->load());

	// Trusted certificates chain which must not be verified.
	// Push onto this chain the root certificate.
	X509CertificateChain trustedCertificateChain;
	trustedCertificateChain.addCertificate(rootCertificateLoader->load());

	const Verifier verifyObject(trustedCertificateChain, untrustedCertificateChain,
		std::make_shared<CertificatePemFileLoader>(verifyingCertificatePath), X509CrlList());

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