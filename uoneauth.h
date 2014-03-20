#ifndef UONEAUTH_H
#define UONEAUTH_H

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

typedef void Token_;
typedef void SSOService_;
typedef void ErrorResponse_;

#ifdef __cplusplus
extern "C" {
#endif

Token_ *tokenCopy(Token_ *token);
char *tokenSignURL(Token_ *token, const char *method, const char *url, int asQuery);
void tokenDelete(Token_ *token);

SSOService_ *newSSOService();
void ssoServiceGetCredentials(SSOService_ *service);
void ssoServiceLogin(SSOService_ *service, char *email, char *password, char *twoFactor);
void ssoServiceDelete(SSOService_ *service);

char *errorResponseString(ErrorResponse_ *errorResponse);

#ifdef __cplusplus
}
#endif

#endif // UONEAUTH_H
