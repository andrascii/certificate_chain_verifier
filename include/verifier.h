#pragma once

#include "x509_certificate_chain.h"
#include "x509_crl_list.h"

namespace verifier
{

class ICertificateLoader;

//! Do the verification of the certificates chain.
//! Verifies all certificates except that are in the trusted chain.
class Verifier final
{
public:
	Verifier(const X509CertificateChain& trustedCertificateChain,
		const X509CertificateChain& untrustedCertificateChain,
		const std::shared_ptr<ICertificateLoader>& verifyingCertificateLoader,
		const X509CrlList& crlList);

	//! Returns pair where first element is true if verification successfully done.
	//! Returns false and in this case also contains error message in the second pair element.
	std::pair<bool, std::string> verify() const;

private:
	std::pair<bool, std::string> check(X509_STORE* context) const;
	std::string interpretError(int error) const;

private:
	X509CertificateChain m_trustedCertificateChain;
	X509CertificateChain m_untrustedCertificateChain;
	std::shared_ptr<ICertificateLoader> m_verifyingCertificateLoader;
	X509CrlList m_crlList;
};

}