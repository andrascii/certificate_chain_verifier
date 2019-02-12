#pragma once

#include "icertificate_loader.h"

namespace verifier
{

//! Loads certificate from file in PEM format
class CertificatePemFileLoader final : public ICertificateLoader
{
public:
	CertificatePemFileLoader(const std::string& path);

	virtual X509Certificate load() const override;

private:
	const std::string m_path;
};

}