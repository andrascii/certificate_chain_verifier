#pragma once

namespace verifier
{

class ICertificateLoader;

class CertificateLoaderFactory final
{
public:
	enum LoaderType
	{
		LoaderPemFile
	};

	std::shared_ptr<ICertificateLoader> getLoader(LoaderType type) const;
};

}