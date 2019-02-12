#pragma once

namespace verifier
{

using X509Certificate = std::shared_ptr<X509>;

class X509CertificateChain final
{
public:
	X509CertificateChain();

	void addCertificate(const X509Certificate& certificate);
	STACK_OF(X509)* get() const;

private:
	std::vector<X509Certificate> m_certificates;
	std::shared_ptr<STACK_OF(X509)> m_nativeChain;
};

}