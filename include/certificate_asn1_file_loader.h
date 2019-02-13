#pragma once

#include "icertificate_loader.h"

namespace verifier
{

class CertificateAsn1FileLoader final : public ICertificateLoader
{
public:
	CertificateAsn1FileLoader(const std::string& asn1FilePath);

	virtual X509Certificate load() const override;

private:
	std::vector<uint8_t> fileContent() const;

private:
	std::string m_asn1FilePath;
};

}