#include "certificate_asn1_file_loader.h"
#include "certificate_asn1_loader.h"

namespace verifier
{

CertificateAsn1FileLoader::CertificateAsn1FileLoader(const std::string& asn1FilePath)
	: m_asn1FilePath(asn1FilePath)
{
}

X509Certificate CertificateAsn1FileLoader::load() const
{
	std::ifstream input(m_asn1FilePath, std::ios_base::binary);
	std::vector<uint8_t> buffer = fileContent();

	CertificateAsn1Loader loaderHelper(std::move(buffer));
	return loaderHelper.load();
}

std::vector<uint8_t> CertificateAsn1FileLoader::fileContent() const
{
	std::ifstream input(m_asn1FilePath, std::ios_base::binary | std::ios_base::ate);
	const std::fstream::pos_type position = input.tellg();

	input.seekg(0, std::ios_base::beg);

	std::vector<uint8_t> buffer(position);
	input.read(reinterpret_cast<char*>(buffer.data()), position);

	return buffer;
}

}