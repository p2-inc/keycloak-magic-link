package io.phasetwo.keycloak.magic.auth.cloudflare;

import static io.phasetwo.keycloak.magic.auth.util.TurnstileMocks.ACTION;
import static io.phasetwo.keycloak.magic.auth.util.TurnstileMocks.SITE_KEY;
import static io.phasetwo.keycloak.magic.auth.util.TurnstileMocks.completeConfig;
import static io.phasetwo.keycloak.magic.auth.util.TurnstileMocks.configWithout;
import static io.phasetwo.keycloak.magic.auth.util.TurnstileMocks.siteverifyBody;
import static io.phasetwo.keycloak.magic.auth.util.TurnstileMocks.stubSiteverify;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.RETURNS_SELF;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import io.phasetwo.keycloak.magic.auth.util.CloudflareTurnstile;
import jakarta.ws.rs.core.MultivaluedHashMap;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.authentication.FormContext;
import org.keycloak.authentication.ValidationContext;
import org.keycloak.common.ClientConnection;
import org.keycloak.events.Errors;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.services.messages.Messages;
import org.mockito.ArgumentCaptor;

class CloudflareTurnstileFormActionTest {

  private final CloudflareTurnstileFormAction formAction = new CloudflareTurnstileFormAction();

  private ValidationContext context;
  private KeycloakSession session;
  private MultivaluedHashMap<String, String> formData;

  @BeforeEach
  void setUp() {
    context = mock(ValidationContext.class);
    session = mock(KeycloakSession.class);
    formData = new MultivaluedHashMap<>();

    HttpRequest request = mock(HttpRequest.class);
    ClientConnection connection = mock(ClientConnection.class);
    when(context.getSession()).thenReturn(session);
    when(context.getHttpRequest()).thenReturn(request);
    when(context.getConnection()).thenReturn(connection);
    when(request.getDecodedFormParameters()).thenReturn(formData);
    when(connection.getRemoteAddr()).thenReturn("127.0.0.1");
  }

  @Test
  void buildPageRendersWidgetWhenUserIsAlreadySet() {
    FormContext formContext = mock(FormContext.class);
    LoginFormsProvider form = mock(LoginFormsProvider.class, RETURNS_SELF);
    when(formContext.getAuthenticatorConfig()).thenReturn(completeConfig());
    when(formContext.getUser()).thenReturn(mock(UserModel.class));

    formAction.buildPage(formContext, form);

    verify(form).setAttribute("turnstileRequired", true);
    verify(form).setAttribute("turnstileSiteKey", SITE_KEY);
    verify(form).setAttribute("turnstileAction", ACTION);
  }

  @Test
  void buildPageShowsErrorWhenNotConfigured() {
    FormContext formContext = mock(FormContext.class);
    LoginFormsProvider form = mock(LoginFormsProvider.class, RETURNS_SELF);
    when(formContext.getAuthenticatorConfig())
        .thenReturn(configWithout(CloudflareTurnstile.CF_SITE_SECRET));

    formAction.buildPage(formContext, form);

    verify(form).addError(any(FormMessage.class));
    verify(form, never()).setAttribute(anyString(), any());
  }

  @Test
  void validateFailsClosedWithoutConfig() {
    useConfig(null);
    formData.putSingle(CloudflareTurnstile.CF_TURNSTILE_RESPONSE, "token");

    formAction.validate(context);

    verifyValidationError(CloudflareTurnstile.MSG_CAPTCHA_NOT_CONFIGURED);
  }

  @Test
  void validateFailsClosedWhenNotConfigured() {
    useConfig(configWithout(CloudflareTurnstile.CF_SITE_SECRET));
    formData.putSingle(CloudflareTurnstile.CF_TURNSTILE_RESPONSE, "token");

    formAction.validate(context);

    verifyValidationError(CloudflareTurnstile.MSG_CAPTCHA_NOT_CONFIGURED);
    verify(session, never()).getProvider(any());
  }

  @Test
  void validateRejectsBlankTokenWithoutCallingSiteverify() {
    useConfig(completeConfig());

    formAction.validate(context);

    verifyValidationError(Messages.RECAPTCHA_FAILED);
    verify(session, never()).getProvider(any());
  }

  @Test
  void validateRejectsRefusedToken() throws Exception {
    useConfig(completeConfig());
    formData.putSingle(CloudflareTurnstile.CF_TURNSTILE_RESPONSE, "token");
    stubSiteverify(session, 200, siteverifyBody(false, ACTION));

    formAction.validate(context);

    verifyValidationError(Messages.RECAPTCHA_FAILED);
    assertFalse(formData.containsKey(CloudflareTurnstile.CF_TURNSTILE_RESPONSE));
  }

  @Test
  void validateSucceedsOnAcceptedToken() throws Exception {
    useConfig(completeConfig());
    formData.putSingle(CloudflareTurnstile.CF_TURNSTILE_RESPONSE, "token");
    stubSiteverify(session, 200, siteverifyBody(true, ACTION));

    formAction.validate(context);

    verify(context).success();
    verify(context, never()).validationError(any(), any());
  }

  private void useConfig(AuthenticatorConfigModel config) {
    when(context.getAuthenticatorConfig()).thenReturn(config);
  }

  @SuppressWarnings("unchecked")
  private void verifyValidationError(String message) {
    ArgumentCaptor<List<FormMessage>> errors = ArgumentCaptor.forClass(List.class);
    verify(context).error(Errors.INVALID_REGISTRATION);
    verify(context).validationError(any(), errors.capture());
    verify(context).excludeOtherErrors();
    verify(context, never()).success();
    assertEquals(1, errors.getValue().size());
    assertEquals(CloudflareTurnstile.CF_TURNSTILE_RESPONSE, errors.getValue().get(0).getField());
    assertEquals(message, errors.getValue().get(0).getMessage());
  }
}
