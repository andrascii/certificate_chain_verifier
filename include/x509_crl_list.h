#pragma once

namespace verifier
{

using X509Crl = std::shared_ptr<X509_CRL>;

class X509CrlList final
{
public:
	X509CrlList();

	void addCrl(const X509Crl& crl);
	STACK_OF(X509_CRL)* get() const;

private:
	std::vector<X509Crl> m_crls;
	std::shared_ptr<STACK_OF(X509_CRL)> m_nativeChain;
};

}