#pragma once

#include "icertificate_loader.h"

namespace verifier
{

class CertificateAsn1Loader final : public ICertificateLoader
{
public:
	CertificateAsn1Loader(const std::vector<uint8_t>& asn1Buffer);

	virtual X509Certificate load() const override;

private:
	std::vector<uint8_t> m_asn1Buffer;
};

}