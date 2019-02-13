#include "certificate_asn1_loader.h"

namespace verifier
{

CertificateAsn1Loader::CertificateAsn1Loader(std::vector<uint8_t>&& asn1Buffer)
	: m_asn1Buffer(std::move(asn1Buffer))
{
}

CertificateAsn1Loader::CertificateAsn1Loader(const std::vector<uint8_t>& asn1Buffer)
	: m_asn1Buffer(asn1Buffer)
{
}

X509Certificate CertificateAsn1Loader::load() const
{
	const auto* asn1CertificateBuffer = reinterpret_cast<const unsigned char*>(m_asn1Buffer.data());
	return std::shared_ptr<X509>(d2i_X509(nullptr, &asn1CertificateBuffer, static_cast<long>(m_asn1Buffer.size())), X509_free);
}

}