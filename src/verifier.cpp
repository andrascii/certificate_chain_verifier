#include "verifier.h"
#include "finally.h"

namespace verifier
{

Verifier::Verifier(const std::string& rootCertificatePath, const std::string& endCertificatePath)
	: m_rootCertificatePath(rootCertificatePath)
	, m_endCertificatePath(endCertificatePath)
{
}

std::pair<bool, std::string> Verifier::verify() const
{
	X509_STORE* certContext = nullptr;
	X509_LOOKUP* lookup = nullptr;

	certContext = X509_STORE_new();

	Finally finallyObject([&certContext]
	{
		if (certContext)
		{
			X509_STORE_free(certContext);
		}
	});

	if (!certContext)
	{
		return std::make_pair(false, "Cannot create a certificate context");
	}

	OpenSSL_add_all_algorithms();

	lookup = X509_STORE_add_lookup(certContext, X509_LOOKUP_file());

	if (!lookup || !X509_LOOKUP_load_file(lookup, m_rootCertificatePath.data(), X509_FILETYPE_PEM))
	{
		return std::make_pair(false, "Cannot add a lookup or create a lookup file");
	}

	lookup = X509_STORE_add_lookup(certContext, X509_LOOKUP_hash_dir());

	if (!lookup)
	{
		return std::make_pair(false, "Cannot add a lookup");
	}

	X509_LOOKUP_add_dir(lookup, nullptr, X509_FILETYPE_DEFAULT);

	return check(certContext, m_endCertificatePath);
}

X509* Verifier::certificateFromPemFile(const std::string& path) const
{
	X509* x = nullptr;
	BIO* cert;

	Finally finallyObject([&cert]
	{
		if (cert)
		{
			BIO_free(cert);
		}
	});

	if ((cert = BIO_new(BIO_s_file())) == nullptr)
	{
		return x;
	}

	if (BIO_read_filename(cert, path.data()) <= 0)
	{
		return x;
	}

	x = PEM_read_bio_X509_AUX(cert, nullptr, nullptr, nullptr);

	return x;
}

std::pair<bool, std::string> Verifier::check(X509_STORE* context, const std::string& path) const
{
	X509* x509Certificate = nullptr;

	Finally finallyObject([&x509Certificate]
	{
		if (x509Certificate)
		{
			X509_free(x509Certificate);
		}
	});

	X509_STORE_CTX* x509StoreContext;

	x509Certificate = certificateFromPemFile(path);

	if (!x509Certificate)
	{
		return std::make_pair(false, std::string("Invalid resulted X509 certificate"));
	}

	x509StoreContext = X509_STORE_CTX_new();

	if (!x509StoreContext)
	{
		return std::make_pair(false, std::string("Cannot create X509 store context"));
	}

	X509_STORE_set_flags(context, 0);

	if (!X509_STORE_CTX_init(x509StoreContext, context, x509Certificate, 0))
	{
		return std::make_pair(false, std::string("Cannot initialize X509 store context"));
	}

	const bool allIsOk = X509_verify_cert(x509StoreContext) == 1;
	const std::string errorMessage = interpretError(X509_STORE_CTX_get_error(x509StoreContext));

	X509_STORE_CTX_free(x509StoreContext);

	return std::make_pair(allIsOk, errorMessage);
}

std::string Verifier::interpretError(int error) const
{
	switch (error)
	{
		case X509_V_OK:
		{
			return std::string("ok: "
				"the operation was successful.");
		}
		case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
		{
			return std::string("unable to get issuer certificate: "
				"the issuer certificate could not be found: this occurs if the issuer certificate of an untrusted certificate cannot be found.");
		}
		case X509_V_ERR_UNABLE_TO_GET_CRL:
		{
			return std::string("unable to get certificate CRL: "
				"the CRL of a certificate could not be found.");
		}
		case X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE:
		{
			return std::string("unable to decrypt certificate's signature: "
				"the certificate signature could not be decrypted. "
				"This means that the actual signature value could not be determined rather than it not matching the expected value, this is only meaningful for RSA keys.");
		}
		case X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE:
		{
			return std::string("unable to decrypt CRL 's signature: "
				"the CRL signature could not be decrypted: this means that the actual signature value could not be determined rather than it not matching the expected value. Unused.");
		}
		case X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY:
		{
			return std::string("unable to decode issuer public key: "
				"the public key in the certificate SubjectPublicKeyInfo could not be read.");
		}
		case X509_V_ERR_CERT_SIGNATURE_FAILURE:
		{
			return std::string("certificate signature failure: "
				"the signature of the certificate is invalid.");
		}
		case X509_V_ERR_CRL_SIGNATURE_FAILURE:
		{
			return std::string("CRL signature failure: "
				"the signature of the certificate is invalid.");
		}
		case X509_V_ERR_CERT_NOT_YET_VALID:
		{
			return std::string("certificate is not yet valid: "
				"the certificate is not yet valid: the notBefore date is after the current time.");
		}
		case X509_V_ERR_CERT_HAS_EXPIRED:
		{
			return std::string("certificate has expired: "
				"the certificate has expired: that is the notAfter date is before the current time.");
		}
		case X509_V_ERR_CRL_NOT_YET_VALID:
		{
			return std::string("CRL is not yet valid: "
				"the CRL is not yet valid.");
		}
		case X509_V_ERR_CRL_HAS_EXPIRED:
		{
			return std::string("CRL has expired: "
				"the CRL has expired.");
		}
		case X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
		{
			return std::string("format error in certificate's notBefore field: "
				"the certificate notBefore field contains an invalid time.");
		}
		case X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:
		{
			return std::string("format error in certificate's notAfter field: "
				"the certificate notAfter field contains an invalid time.");
		}
		case X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD:
		{
			return std::string("format error in CRL 's lastUpdate field: "
				"the CRL lastUpdate field contains an invalid time.");
		}
		case X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD:
		{
			return std::string("format error in CRL 's nextUpdate field: "
				"the CRL nextUpdate field contains an invalid time.");
		}
		case X509_V_ERR_OUT_OF_MEM:
		{
			return std::string("out of memory: "
				"an error occurred trying to allocate memory. This should never happen.");
		}
		case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
		{
			return std::string("self signed certificate: "
				"the passed certificate is self signed and the same certificate cannot be found in the list of trusted certificates.");
		}
		case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
		{
			return std::string("self signed certificate in certificate chain: "
				"the certificate chain could be built up using the untrusted certificates but the root could not be found locally.");
		}
		case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
		{
			return std::string("unable to get local issuer certificate: "
				"the issuer certificate of a locally looked up certificate could not be found. "
				"This normally means the list of trusted certificates is not complete.");
		}
		case X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE:
		{
			return std::string("unable to verify the first certificate: "
				"no signatures could be verified because the chain contains only one certificate and it is not self signed.");
		}
		case X509_V_ERR_CERT_CHAIN_TOO_LONG:
		{
			return std::string("certificate chain too long: "
				"the certificate chain length is greater than the supplied maximum depth. Unused.");
		}
		case X509_V_ERR_CERT_REVOKED:
		{
			return std::string("certificate revoked: "
				"the certificate has been revoked.");
		}
		case X509_V_ERR_INVALID_CA:
		{
			return std::string("invalid CA certificate: "
				"a CA certificate is invalid. Either it is not a CA or its extensions are not consistent with the supplied purpose.");
		}
		case X509_V_ERR_PATH_LENGTH_EXCEEDED:
		{
			return std::string("path length constraint exceeded: "
				"the basicConstraints path length parameter has been exceeded.");
		}
		case X509_V_ERR_INVALID_PURPOSE:
		{
			return std::string("unsupported certificate purpose: "
				"the supplied certificate cannot be used for the specified purpose.");
		}
		case X509_V_ERR_CERT_UNTRUSTED:
		{
			return std::string("certificate not trusted: "
				"the root CA is not marked as trusted for the specified purpose.");
		}
		case X509_V_ERR_CERT_REJECTED:
		{
			return std::string("certificate rejected: "
				"the root CA is marked to reject the specified purpose.");
		}
		case X509_V_ERR_SUBJECT_ISSUER_MISMATCH:
		{
			return std::string("subject issuer mismatch: "
				"the current candidate issuer certificate was rejected because its subject name did not match the issuer name of the current certificate. "
				"This is only set if issuer check debugging is enabled it is used for status notification and is not in itself an error.");
		}
		case X509_V_ERR_AKID_SKID_MISMATCH:
		{
			return std::string("authority and subject key identifier mismatch: "
				"the current candidate issuer certificate was rejected because its subject key identifier was present and did not match the authority key identifier current certificate. "
				"This is only set if issuer check debugging is enabled it is used for status notification and is not in itself an error.");
		}
		case X509_V_ERR_AKID_ISSUER_SERIAL_MISMATCH:
		{
			return std::string("authority and issuer serial number mismatch: "
				"the current candidate issuer certificate was rejected because its issuer name and serial number was present and did not match the authority key identifier of the current certificate. "
				"This is only set if issuer check debugging is enabled it is used for status notification and is not in itself an error.");
		}
		case X509_V_ERR_KEYUSAGE_NO_CERTSIGN:
		{
			return std::string("key usage does not include certificate signing: "
				"the current candidate issuer certificate was rejected because its keyUsage extension does not permit certificate signing. "
				"This is only set if issuer check debugging is enabled it is used for status notification and is not in itself an error.");
		}
		case X509_V_ERR_INVALID_EXTENSION:
		{
			return std::string("invalid or inconsistent certificate extension: "
				"A certificate extension had an invalid value (for example an incorrect encoding) or some value inconsistent with other extensions.");
		}
		case X509_V_ERR_INVALID_POLICY_EXTENSION:
		{
			return std::string("invalid or inconsistent certificate policy extension: "
				"A certificate policies extension had an invalid value (for example an incorrect encoding) or some value inconsistent with other extensions. "
				"This error only occurs if policy processing is enabled.");
		}
		case X509_V_ERR_NO_EXPLICIT_POLICY:
		{
			return std::string("no explicit policy: "
				"The verification flags were set to require and explicit policy but none was present.");
		}
		case X509_V_ERR_DIFFERENT_CRL_SCOPE:
		{
			return std::string("Different CRL scope: "
				"The only CRLs that could be found did not match the scope of the certificate.");
		}
		case X509_V_ERR_UNSUPPORTED_EXTENSION_FEATURE:
		{
			return std::string("Unsupported extension feature: "
				"Some feature of a certificate extension is not supported. Unused.");
		}
		case X509_V_ERR_PERMITTED_VIOLATION:
		{
			return std::string("permitted subtree violation: "
				"A name constraint violation occurred in the permitted subtrees.");
		}
		case X509_V_ERR_EXCLUDED_VIOLATION:
		{
			return std::string("excluded subtree violation: "
				"A name constraint violation occurred in the excluded subtrees.");
		}
		case X509_V_ERR_SUBTREE_MINMAX:
		{
			return std::string("name constraints minimum and maximum not supported: "
				"A certificate name constraints extension included a minimum or maximum field: this is not supported.");
		}
		case X509_V_ERR_UNSUPPORTED_CONSTRAINT_TYPE:
		{
			return std::string("unsupported name constraint type: "
				"An unsupported name constraint type was encountered. OpenSSL currently only supports directory name, DNS name, email and URI types.");
		}
		case X509_V_ERR_UNSUPPORTED_CONSTRAINT_SYNTAX:
		{
			return std::string("unsupported or invalid name constraint syntax: "
				"The format of the name constraint is not recognized: for example an email address format of a form not mentioned in RFC3280 . "
				"This could be caused by a garbage extension or some new feature not currently supported.");
		}
		case X509_V_ERR_CRL_PATH_VALIDATION_ERROR:
		{
			return std::string("CRL path validation error: "
				"An error occurred when attempting to verify the CRL path. This error can only happen if extended CRL checking is enabled.");
		}
		case X509_V_ERR_APPLICATION_VERIFICATION:
		{
			return std::string("application verification failure: "
				"an application specific error. This will never be returned unless explicitly set by an application.");
		}
		case X509_V_ERR_EE_KEY_TOO_SMALL:
		{
			return std::string("EE certificate key too weak.");
		}
		case X509_V_ERR_CA_KEY_TOO_SMALL:
		{
			return std::string("CA certificate key too weak.");
		}
		case X509_V_ERR_CA_MD_TOO_WEAK:
		{
			return std::string(".......................");
		}
		default:
		{
			return std::string("Unknown error");
		}
	}
}

} // namespace