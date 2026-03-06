const testRealmUri = Cypress.config('baseUrl') + "realms/test-realm";
const testRealmAuthUri = testRealmUri.concat("/protocol/openid-connect/auth");
const testRealmLoginUri = testRealmAuthUri.concat(
    '?response_type=code',
    '&client_id=account',
    '&scope=openid',
    '&redirect_uri=', testRealmUri.concat("/account")
);

const mailhogBaseUrl = Cypress.env('mailhogUrl')

export {
    testRealmLoginUri,
    testRealmUri,
    mailhogBaseUrl,
}
