#include "finally.h"
#include "verifier.h"

int main()
{
	OPENSSL_init_ssl(OPENSSL_INIT_LOAD_CONFIG, NULL);

	const std::string rootCertificatePath("C:\\Users\\a.pugachev\\Desktop\\id256_A_CA.cer");
	const std::string endCertificatePath("C:\\Users\\a.pugachev\\Desktop\\edvards.cer");

	const verifier::Verifier verifyObject(rootCertificatePath, endCertificatePath);

	const std::pair<bool, std::string> result = verifyObject.verify();

	std::cout << "Information about operation: " << result.second << std::endl;
	std::cin.get();
}