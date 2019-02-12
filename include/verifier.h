#pragma once

#include "x509_certificate_chain.h"

namespace verifier
{

class ICertificateLoader;

//! Do the verification of the certificates chain.
//! Verifies all certificates except root certificate.
class Verifier final
{
public:
	Verifier(const std::shared_ptr<ICertificateLoader>& rootCertificateLoader,
		const std::shared_ptr<ICertificateLoader>& endCertificateLoader,
		const X509CertificateChain& untrustedCertificateChain);

	//! Returns pair where first element is true if verification successfully done.
	//! Returns false and in this case also contains error message in the second pair element.
	std::pair<bool, std::string> verify() const;

private:
	std::pair<bool, std::string> check(X509_STORE* context) const;
	std::string interpretError(int error) const;

private:
	std::shared_ptr<ICertificateLoader> m_rootCertificateLoader;
	std::shared_ptr<ICertificateLoader> m_endCertificateLoader;
	X509CertificateChain m_untrustedCertificateChain;
};

}