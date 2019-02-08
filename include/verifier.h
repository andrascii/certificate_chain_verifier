#pragma once

namespace verifier
{

class Verifier final
{
public:
	Verifier(const std::string& rootCertificatePath, const std::string& endCertificatePath);

	std::pair<bool, std::string> verify() const;

private:
	X509* certificateFromPemFile(const std::string& path) const;
	std::pair<bool, std::string> check(X509_STORE* context, const std::string& path) const;
	std::string interpretError(int error) const;

private:
	const std::string m_rootCertificatePath;
	const std::string m_endCertificatePath;
};

}