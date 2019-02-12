#include "certificate_loader_factory.h"
#include "certificate_pem_file_loader.h"

namespace verifier
{

std::shared_ptr<ICertificateLoader>
CertificateLoaderFactory::getLoader(LoaderType type) const
{
	switch (type)
	{
		case LoaderPemFile:
		{
			//return std::make_shared<CertificatePemFileLoader>();
			return nullptr;
		}
	}

	throw std::runtime_error("Unknown loader type");
}

}