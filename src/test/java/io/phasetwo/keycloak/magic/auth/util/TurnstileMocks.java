package io.phasetwo.keycloak.magic.auth.util;

import static io.phasetwo.keycloak.magic.auth.util.CloudflareTurnstile.CF_ACTION;
import static io.phasetwo.keycloak.magic.auth.util.CloudflareTurnstile.CF_SITE_KEY;
import static io.phasetwo.keycloak.magic.auth.util.CloudflareTurnstile.CF_SITE_SECRET;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import org.apache.http.StatusLine;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.keycloak.connections.httpclient.HttpClientProvider;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;

/** Shared fixtures for the Turnstile unit tests. */
public final class TurnstileMocks {

  public static final String SITE_KEY = "site-key";
  public static final String SECRET = "secret";
  public static final String ACTION = "login";

  private TurnstileMocks() {}

  /** A config with the site key, secret and action all set. */
  public static AuthenticatorConfigModel completeConfig() {
    Map<String, String> config = new HashMap<>();
    config.put(CF_SITE_KEY, SITE_KEY);
    config.put(CF_SITE_SECRET, SECRET);
    config.put(CF_ACTION, ACTION);
    return configModel(config);
  }

  /** A complete config with {@code key} removed. */
  public static AuthenticatorConfigModel configWithout(String key) {
    AuthenticatorConfigModel model = completeConfig();
    model.getConfig().remove(key);
    return model;
  }

  public static AuthenticatorConfigModel configModel(Map<String, String> config) {
    AuthenticatorConfigModel model = new AuthenticatorConfigModel();
    model.setAlias("turnstile");
    model.setConfig(config);
    return model;
  }

  /** Stubs {@code session}'s HTTP client so siteverify answers with {@code status} and {@code body}. */
  public static CloseableHttpClient stubSiteverify(KeycloakSession session, int status, String body)
      throws IOException {
    StatusLine statusLine = mock(StatusLine.class);
    when(statusLine.getStatusCode()).thenReturn(status);
    when(statusLine.getReasonPhrase()).thenReturn("status " + status);

    CloseableHttpResponse response = mock(CloseableHttpResponse.class);
    when(response.getStatusLine()).thenReturn(statusLine);
    when(response.getEntity()).thenReturn(new StringEntity(body, ContentType.APPLICATION_JSON));

    CloseableHttpClient httpClient = mock(CloseableHttpClient.class);
    when(httpClient.execute(any(HttpUriRequest.class))).thenReturn(response);

    HttpClientProvider provider = mock(HttpClientProvider.class);
    when(provider.getHttpClient()).thenReturn(httpClient);
    when(session.getProvider(HttpClientProvider.class)).thenReturn(provider);
    return httpClient;
  }

  /** A siteverify JSON body. */
  public static String siteverifyBody(boolean success, String action) {
    return "{\"success\":" + success + ",\"action\":\"" + action + "\"}";
  }
}
