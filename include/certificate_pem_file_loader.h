#pragma once

#include "icertificate_loader.h"

namespace verifier
{

class CertificatePemFileLoader final : public ICertificateLoader
{
public:
	CertificatePemFileLoader(const std::string& path);

	virtual X509Certificate load() const override;

private:
	const std::string m_path;
};

}