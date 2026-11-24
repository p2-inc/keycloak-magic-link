package io.phasetwo.keycloak.magic.auth.cloudflare;

import static io.phasetwo.keycloak.magic.auth.util.TurnstileMocks.ACTION;
import static io.phasetwo.keycloak.magic.auth.util.TurnstileMocks.completeConfig;
import static io.phasetwo.keycloak.magic.auth.util.TurnstileMocks.configWithout;
import static io.phasetwo.keycloak.magic.auth.util.TurnstileMocks.siteverifyBody;
import static io.phasetwo.keycloak.magic.auth.util.TurnstileMocks.stubSiteverify;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.RETURNS_SELF;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import io.phasetwo.keycloak.magic.auth.util.CloudflareTurnstile;
import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.Response;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.common.ClientConnection;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.utils.FormMessage;

class CloudflareTurnstileAuthenticatorTest {

  private final CloudflareTurnstileAuthenticator authenticator =
      new CloudflareTurnstileAuthenticator();

  private AuthenticationFlowContext context;
  private KeycloakSession session;
  private LoginFormsProvider form;
  private MultivaluedHashMap<String, String> formData;
  private Response challengePage;
  private Response errorPage;

  @BeforeEach
  void setUp() {
    context = mock(AuthenticationFlowContext.class);
    session = mock(KeycloakSession.class);
    form = mock(LoginFormsProvider.class, RETURNS_SELF);
    formData = new MultivaluedHashMap<>();
    challengePage = mock(Response.class);
    errorPage = mock(Response.class);

    AuthenticationExecutionModel execution = new AuthenticationExecutionModel();
    execution.setId("execution-id");
    HttpRequest request = mock(HttpRequest.class);
    ClientConnection connection = mock(ClientConnection.class);
    RealmModel realm = mock(RealmModel.class);

    when(context.getSession()).thenReturn(session);
    when(context.form()).thenReturn(form);
    when(context.getExecution()).thenReturn(execution);
    when(context.getHttpRequest()).thenReturn(request);
    when(context.getConnection()).thenReturn(connection);
    when(context.getRealm()).thenReturn(realm);
    when(request.getDecodedFormParameters()).thenReturn(formData);
    when(connection.getRemoteAddr()).thenReturn("127.0.0.1");
    when(form.createForm("cf-captcha.ftl")).thenReturn(challengePage);
    when(form.createErrorPage(any())).thenReturn(errorPage);
  }

  @Test
  void authenticateShowsChallengeWhenConfigured() {
    useConfig(completeConfig());

    authenticator.authenticate(context);

    verify(context).challenge(challengePage);
    verify(form).setAttribute("captchaSiteKey", "site-key");
  }

  @Test
  void authenticateFailsClosedWhenNotConfigured() {
    useConfig(configWithout(CloudflareTurnstile.CF_SITE_SECRET));

    authenticator.authenticate(context);

    verify(form).setError(CloudflareTurnstile.MSG_CAPTCHA_NOT_CONFIGURED);
    verify(context).failure(AuthenticationFlowError.INTERNAL_ERROR, errorPage);
    verify(context, never()).challenge(any());
  }

  @Test
  void authenticateFailsClosedWithoutConfig() {
    useConfig(null);

    authenticator.authenticate(context);

    verify(context).failure(AuthenticationFlowError.INTERNAL_ERROR, errorPage);
  }

  @Test
  void actionFailsClosedWhenNotConfigured() {
    useConfig(configWithout(CloudflareTurnstile.CF_ACTION));
    formData.putSingle(CloudflareTurnstile.CF_TURNSTILE_RESPONSE, "token");

    authenticator.action(context);

    verify(context).failure(AuthenticationFlowError.INTERNAL_ERROR, errorPage);
    verify(context, never()).success();
  }

  @Test
  void actionRechallengesOnBlankToken() {
    useConfig(completeConfig());

    authenticator.action(context);

    verifyRechallenged();
    verify(session, never()).getProvider(any());
  }

  @Test
  void actionRechallengesOnRejectedToken() throws Exception {
    useConfig(completeConfig());
    formData.putSingle(CloudflareTurnstile.CF_TURNSTILE_RESPONSE, "token");
    stubSiteverify(session, 200, siteverifyBody(false, ACTION));

    authenticator.action(context);

    verifyRechallenged();
  }

  @Test
  void actionSucceedsOnAcceptedToken() throws Exception {
    useConfig(completeConfig());
    formData.putSingle(CloudflareTurnstile.CF_TURNSTILE_RESPONSE, "token");
    stubSiteverify(session, 200, siteverifyBody(true, ACTION));

    authenticator.action(context);

    verify(context).success();
    verify(context, never()).failureChallenge(any(), any());
  }

  private void useConfig(AuthenticatorConfigModel config) {
    when(context.getAuthenticatorConfig()).thenReturn(config);
  }

  private void verifyRechallenged() {
    verify(form)
        .addError(
            argThat(
                (FormMessage m) -> CloudflareTurnstile.MSG_CAPTCHA_FAILED.equals(m.getMessage())));
    verify(form).setExecution("execution-id");
    verify(context)
        .failureChallenge(eq(AuthenticationFlowError.INVALID_CREDENTIALS), eq(challengePage));
    verify(context, never()).success();
    verify(form, never()).setError(anyString());
  }
}
