#include "x509_crl_list.h"

namespace verifier
{

X509CrlList::X509CrlList()
	: m_nativeChain(sk_X509_CRL_new_null(), sk_X509_CRL_free)
{
}

void X509CrlList::addCrl(const X509Crl& crl)
{
	m_crls.push_back(crl);
	sk_X509_CRL_push(m_nativeChain.get(), crl.get());
}

STACK_OF(X509_CRL)* X509CrlList::get() const
{
	return m_nativeChain.get();
}

}