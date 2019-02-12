#include "x509_certificate_chain.h"

namespace verifier
{

X509CertificateChain::X509CertificateChain()
	: m_nativeChain(sk_X509_new_null(), sk_X509_free)
{
}

void X509CertificateChain::addCertificate(const X509Certificate& certificate)
{
	m_certificates.push_back(certificate);
	sk_X509_push(m_nativeChain.get(), certificate.get());
}

STACK_OF(X509)* X509CertificateChain::get() const
{
	return m_nativeChain.get();
}

}