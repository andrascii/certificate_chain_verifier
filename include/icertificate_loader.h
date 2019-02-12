#pragma once

#include "x509_certificate_chain.h"

namespace verifier
{

class ICertificateLoader
{
public:
	virtual ~ICertificateLoader() = default;
	virtual X509Certificate load() const = 0;
};

}