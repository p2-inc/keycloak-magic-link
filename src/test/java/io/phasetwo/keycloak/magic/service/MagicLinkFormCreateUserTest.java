package io.phasetwo.keycloak.magic.service;

import static io.restassured.RestAssured.given;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;

import io.restassured.response.Response;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import lombok.extern.jbosslog.JBossLog;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.keycloak.admin.client.resource.AuthenticationManagementResource;
import org.keycloak.representations.idm.AuthenticationExecutionInfoRepresentation;
import org.keycloak.representations.idm.AuthenticatorConfigRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.testcontainers.Testcontainers;

/**
 * With "create nonexistent user" on, the magic link form must create a user only for a valid email
 * address. Before, it created a user with the raw input as username and no email for any input.
 */
@JBossLog
public class MagicLinkFormCreateUserTest extends AbstractMagicLinkTest {

  private static final Pattern LOGIN_FORM = Pattern.compile("<form[^>]*id=\"kc-form-login\"[^>]*>");
  private static final Pattern ACTION = Pattern.compile("action=\"([^\"]+)\"");

  @ParameterizedTest
  @CsvSource({
    "foo+, false",
    "foo, false",
    "foo@, false",
    "new-user@phasetwo.io, true",
  })
  void createsUserOnlyForValidEmail(String input, boolean created) {
    Testcontainers.exposeHostPorts(container.getHttpPort());
    RealmRepresentation testRealm = importRealm("/realms/magic-link-basic-setup.json");
    String realm = testRealm.getRealm();
    enableCreateNonexistentUser(realm);

    submitMagicLinkForm(realm, input);

    List<UserRepresentation> users = keycloak.realm(realm).users().search(input, true);
    assertThat("users with username " + input, users.size(), is(created ? 1 : 0));
  }

  private void enableCreateNonexistentUser(String realm) {
    AuthenticationManagementResource flows = keycloak.realm(realm).flows();
    AuthenticationExecutionInfoRepresentation execution =
        flows.getExecutions("Magic Link forms").stream()
            .filter(e -> "ext-magic-form".equals(e.getProviderId()))
            .findFirst()
            .orElseThrow();
    AuthenticatorConfigRepresentation config =
        flows.getAuthenticatorConfig(execution.getAuthenticationConfig());
    config.getConfig().put("ext-magic-create-nonexistent-user", "true");
    flows.updateAuthenticatorConfig(config.getId(), config);
  }

  private void submitMagicLinkForm(String realm, String username) {
    Response loginPage =
        given()
            .baseUri(container.getAuthServerUrl())
            .queryParam("client_id", "security-admin-console")
            .queryParam("redirect_uri", "https://localhost/auth/admin/" + realm + "/console/")
            .queryParam("response_type", "code")
            .queryParam("scope", "openid")
            .queryParam("code_challenge", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
            .queryParam("code_challenge_method", "S256")
            .when()
            .get("realms/" + realm + "/protocol/openid-connect/auth")
            .then()
            .statusCode(200)
            .extract()
            .response();

    Matcher form = LOGIN_FORM.matcher(loginPage.asString());
    assertThat("login form found", form.find());
    Matcher action = ACTION.matcher(form.group());
    assertThat("login form action found", action.find());
    Map<String, String> cookies = loginPage.getCookies();

    given()
        .cookies(cookies)
        .redirects()
        .follow(false)
        .formParam("username", username)
        .when()
        .post(action.group(1).replace("&amp;", "&"))
        .then()
        .extract()
        .response();
  }
}
