#include <string.h>

#include <ssoservice.h>

#include "uoneauth.h"


static char *local_strdup(const char *str)
{
    char *strcopy = 0;
    if (str) {
        size_t len = strlen(str) + 1;
        strcopy = (char *)malloc(len);
        memcpy(strcopy, str, len);
    }
    return strcopy;
}

Token_ *tokenCopy(Token_ *token)
{
	return new UbuntuOne::Token(*static_cast<UbuntuOne::Token*>(token));
}

void tokenDelete(Token_ *token)
{
	delete static_cast<UbuntuOne::Token*>(token);
}

char *tokenSignURL(Token_ *token, const char *method, const char *url, int asQuery)
{
	UbuntuOne::Token *t = static_cast<UbuntuOne::Token*>(token);
	QString result = t->signUrl(url, method, asQuery); // HEADS UP: method<=>url order inverted
	QByteArray ba = result.toUtf8();
	return local_strdup(ba.constData());
}

SSOService_ *newSSOService()
{
	return new UbuntuOne::SSOService();
}

void ssoServiceDelete(SSOService_ *service)
{
	delete static_cast<UbuntuOne::SSOService*>(service);
}

void ssoServiceGetCredentials(SSOService_ *service)
{
	UbuntuOne::SSOService *s = static_cast<UbuntuOne::SSOService*>(service);
	s->getCredentials();
}

void ssoServiceLogin(SSOService_ *service, char *email, char *password, char *twoFactor)
{
	UbuntuOne::SSOService *s = static_cast<UbuntuOne::SSOService*>(service);
	s->login(email, password, twoFactor);
}

char *errorResponseString(ErrorResponse_ *errorResponse)
{
	UbuntuOne::ErrorResponse *e = static_cast<UbuntuOne::ErrorResponse*>(errorResponse);
	QByteArray ba;
	if (!e->message().isEmpty()) {
		ba = e->message().toUtf8();
	} else if (!e->httpReason().isEmpty()) {
		ba = e->httpReason().toUtf8();
	} else {
		ba = "request failed";
	}
	return local_strdup(ba.constData());
}
