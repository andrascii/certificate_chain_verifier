#pragma once

#include "icertificate_loader.h"

namespace verifier
{

//! Loads X509 certificate from ASN1 representation
class CertificateAsn1Loader final : public ICertificateLoader
{
public:
	CertificateAsn1Loader(std::vector<uint8_t>&& asn1Buffer);
	CertificateAsn1Loader(const std::vector<uint8_t>& asn1Buffer);

	virtual X509Certificate load() const override;

private:
	std::vector<uint8_t> m_asn1Buffer;
};

}