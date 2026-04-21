package io.phasetwo.keycloak.magic.web;

import static io.restassured.RestAssured.given;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeoutException;
import lombok.extern.jbosslog.JBossLog;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.DynamicContainer;
import org.junit.jupiter.api.TestFactory;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.testcontainers.Testcontainers;

@JBossLog
@org.testcontainers.junit.jupiter.Testcontainers
@EnabledIfSystemProperty(named = "include.cypress", matches = "true")
public class TurnstileLoginAuthenticatorsTest extends AbstractMagicLinkTest {

  @TestFactory
  @DisplayName("Turnstile Username Password — CAPTCHA passes")
  public List<DynamicContainer> testCaptchaPasses()
      throws IOException, InterruptedException, TimeoutException {

    Testcontainers.exposeHostPorts(container.getHttpPort());

    importRealm("/realms/turnstile-username-password.json");

    stubSiteverify(
        "{\"success\":true,\"action\":\"login\",\"challenge_ts\":\"2024-01-01T00:00:00Z\",\"hostname\":\"localhost\"}");

    return runCypressTests("cypress/e2e/turnstile-login-pass.cy.ts", Map.of());
  }

  @TestFactory
  @DisplayName("Turnstile Username Password — CAPTCHA fails")
  public List<DynamicContainer> testCaptchaFails()
      throws IOException, InterruptedException, TimeoutException {

    Testcontainers.exposeHostPorts(container.getHttpPort());

    importRealm("/realms/turnstile-username-password.json");

    stubSiteverify("{\"success\":false,\"error-codes\":[\"invalid-input-response\"]}");

    return runCypressTests("cypress/e2e/turnstile-login-fail.cy.ts", Map.of());
  }

//  @TestFactory
//  @DisplayName("Turnstile Standalone — CAPTCHA passes")
//  public List<DynamicContainer> testStandaloneCaptchaPasses()
//          throws IOException, InterruptedException, TimeoutException {
//
//      Testcontainers.exposeHostPorts(container.getHttpPort());
//
//      importRealm("/realms/turnstile-standalone.json");
//
//      stubSiteverify(
//              "{\"success\":true,\"action\":\"login\",\"challenge_ts\":\"2024-01-01T00:00:00Z\",\"hostname\":\"localhost\"}");
//
//      return runCypressTests("cypress/e2e/turnstile-standalone-login-pass.cy", Map.of());
//  }

  private void stubSiteverify(String responseBody) {
    given().baseUri(getWireMockAdminUrl()).post("/reset").then().statusCode(200);

    given()
        .baseUri(getWireMockAdminUrl())
        .contentType("application/json")
        .body(
            """
                        {
                          "request":  { "method": "POST", "urlPath": "/turnstile/v0/siteverify" },
                          "response": {
                            "status": 200,
                            "headers": { "Content-Type": "application/json" },
                            "jsonBody": %s
                          }
                        }
                        """
                .formatted(responseBody))
        .post("/mappings")
        .then()
        .statusCode(201);
  }
}
