package io.phasetwo.keycloak.magic.service;

import static io.restassured.RestAssured.given;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.is;

import io.phasetwo.keycloak.magic.Helpers;
import io.restassured.response.Response;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import lombok.extern.jbosslog.JBossLog;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.testcontainers.Testcontainers;

/**
 * A disabled user entering their email in the magic link form must get Keycloak's "Account is
 * disabled" message. Before, the authenticator replaced the flow's event with an untyped one, so
 * {@code enabledUser()} threw "Attempted to define event error without first setting the event
 * type" and the user saw an internal server error (issue #244).
 */
@JBossLog
public class MagicLinkFormDisabledUserTest extends AbstractMagicLinkTest {

  private static final Pattern LOGIN_FORM = Pattern.compile("<form[^>]*id=\"kc-form-login\"[^>]*>");
  private static final Pattern ACTION = Pattern.compile("action=\"([^\"]+)\"");

  @ParameterizedTest
  @ValueSource(strings = {"ext-magic-form", "magic-link-continuation-form"})
  void disabledUserSeesAccountDisabledMessage(String authenticator) {
    Testcontainers.exposeHostPorts(container.getHttpPort());
    RealmRepresentation realm =
        Helpers.loadJson(
            getClass().getResourceAsStream("/realms/magic-link-basic-setup.json"),
            RealmRepresentation.class);
    realm
        .getAuthenticationFlows()
        .forEach(
            flow ->
                flow.getAuthenticationExecutions()
                    .forEach(
                        execution -> {
                          if ("ext-magic-form".equals(execution.getAuthenticator())) {
                            execution.setAuthenticator(authenticator);
                          }
                        }));
    UserRepresentation user = realm.getUsers().getFirst();
    user.setEnabled(false);
    importRealm(realm, keycloak);
    try {
      Response response = submitMagicLinkForm(realm.getRealm(), user.getEmail());
      assertThat(response.asString(), response.getStatusCode(), is(200));
      assertThat(response.asString(), containsString("Account is disabled"));
    } finally {
      keycloak.realm(realm.getRealm()).remove();
    }
  }

  private Response submitMagicLinkForm(String realm, String username) {
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

    return given()
        .cookies(loginPage.getCookies())
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
