/* File:   by_buffer.h */

#ifndef BY_BUFFER_H
#define    BY_BUFFER_H

#include <openssl/x509.h>

#ifdef    __cplusplus
extern "C" {
#endif
#define X509_L_BUF_LOAD    1
#define X509_LOOKUP_load_buf(x,name,type) \
		X509_LOOKUP_ctrl((x),X509_L_BUF_LOAD,(name),(long)(type),NULL)
	X509_LOOKUP_METHOD *X509_LOOKUP_buffer(void);

#ifdef    __cplusplus
}
#endif

#endif    /* BY_BUFFER_H */