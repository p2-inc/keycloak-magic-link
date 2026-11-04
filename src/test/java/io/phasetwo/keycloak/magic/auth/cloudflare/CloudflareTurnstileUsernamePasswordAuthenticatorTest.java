package io.phasetwo.keycloak.magic.auth.cloudflare;

import static io.phasetwo.keycloak.magic.auth.util.TurnstileMocks.ACTION;
import static io.phasetwo.keycloak.magic.auth.util.TurnstileMocks.SITE_KEY;
import static io.phasetwo.keycloak.magic.auth.util.TurnstileMocks.configModel;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.RETURNS_SELF;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import io.phasetwo.keycloak.magic.auth.util.CloudflareTurnstile;
import jakarta.ws.rs.core.Response;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;

/** Covers only the fail-closed guard; the credential paths run in the Testcontainers suite. */
class CloudflareTurnstileUsernamePasswordAuthenticatorTest {

  private CloudflareTurnstileUsernamePasswordAuthenticator authenticator;
  private AuthenticationFlowContext context;
  private Response errorPage;

  @BeforeEach
  void setUp() {
    authenticator =
        new CloudflareTurnstileUsernamePasswordAuthenticator(mock(KeycloakSession.class));
    context = mock(AuthenticationFlowContext.class);
    LoginFormsProvider form = mock(LoginFormsProvider.class, RETURNS_SELF);
    errorPage = mock(Response.class);

    AuthenticationExecutionModel execution = new AuthenticationExecutionModel();
    execution.setId("execution-id");
    when(context.getExecution()).thenReturn(execution);
    when(context.form()).thenReturn(form);
    when(form.createErrorPage(any())).thenReturn(errorPage);

    // Site key entered, secret missing.
    Map<String, String> config = new HashMap<>();
    config.put(CloudflareTurnstile.CF_SITE_KEY, SITE_KEY);
    config.put(CloudflareTurnstile.CF_ACTION, ACTION);
    when(context.getAuthenticatorConfig()).thenReturn(configModel(config));
  }

  @Test
  void authenticateFailsClosedWhenPartiallyConfigured() {
    authenticator.authenticate(context);

    verify(context).failure(AuthenticationFlowError.INTERNAL_ERROR, errorPage);
    verify(context, never()).challenge(any());
  }

  @Test
  void actionFailsClosedWhenPartiallyConfigured() {
    authenticator.action(context);

    verify(context).failure(AuthenticationFlowError.INTERNAL_ERROR, errorPage);
    verify(context, never()).success();
  }
}
