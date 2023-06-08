package io.phasetwo.keycloak.magic;

import io.phasetwo.keycloak.magic.constants.TinyUrlConstants;
import io.phasetwo.keycloak.magic.jpa.TinyUrl;
import io.phasetwo.keycloak.magic.resources.TinyUrlResourceProviderFactory;
import io.phasetwo.keycloak.magic.spi.TinyUrlService;
import java.net.URI;
import java.time.Instant;
import java.util.Random;
import javax.ws.rs.core.UriBuilder;
import lombok.extern.jbosslog.JBossLog;
import org.keycloak.models.Constants;
import org.keycloak.models.KeycloakSession;
import org.keycloak.services.Urls;

@JBossLog
public class TinyUrlHelper {

  public static UriBuilder tinyUriBuilder(
      KeycloakSession session, URI baseUri, String tokenString, String issuedFor, long expiresAt) {
    log.debugf("baseUri: %s, token: %s, issuedFor: %s", baseUri, tokenString, issuedFor);

    String urlKey = generateUrlKey(session, tokenString, issuedFor, expiresAt);
    log.debugf("urlKey: %s", urlKey);

    return Urls.realmBase(baseUri)
        .path(session.getContext().getRealm().getName())
        .path(TinyUrlResourceProviderFactory.PROVIDER_ID)
        .path(urlKey);
  }

  public static UriBuilder actionTokenBuilder(URI baseUri, TinyUrl tinyUrl) {
    log.debugf("baseUri: %s, tokenString: %s", baseUri, tinyUrl.getJwtToken());
    return Urls.realmBase(baseUri)
        .path(tinyUrl.getRealmId())
        .path(TinyUrlConstants.ACTION_TOKEN_URL_PATH)
        .queryParam(Constants.KEY, tinyUrl.getJwtToken())
        .queryParam(Constants.CLIENT_ID, tinyUrl.getClientId());
  }

  private static String generateUrlKey(
      KeycloakSession session, String token, String issuedFor, long expiresAt) {

    TinyUrlService tinyUrlService = session.getProvider(TinyUrlService.class);

    int foundUnique = TinyUrlConstants.NUMBER_OF_RETRIES_FOR_UNIQUE_URL_KEY;
    while (foundUnique-- > 0) {
      try {
        TinyUrl tinyUrl =
            TinyUrl.builder()
                .jwtToken(token)
                .clientId(issuedFor)
                .urlKey(generateAlphanumericString())
                .realmId(session.getContext().getRealm().getName())
                .expiresAt(Instant.ofEpochSecond(expiresAt))
                .build();
        tinyUrlService.addTinyUrl(tinyUrl);
        log.debugf("Generated unique urlKey: %s", tinyUrl.getUrlKey());
        return tinyUrl.getUrlKey();
      } catch (Exception e) {
        log.debugf("Error generating urlKey: %s, retrying", e.getMessage());
      }
    }
    throw new RuntimeException("Unable to generate unique urlKey");
  }

  private static String generateAlphanumericString() {

    final String ALPHANUMERIC_CHARS =
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    final int STRING_LENGTH = 8;

    Random random = new Random();
    StringBuilder sb = new StringBuilder(STRING_LENGTH);

    for (int i = 0; i < STRING_LENGTH; i++) {
      int randomIndex = random.nextInt(ALPHANUMERIC_CHARS.length());
      char randomChar = ALPHANUMERIC_CHARS.charAt(randomIndex);
      sb.append(randomChar);
    }

    return sb.toString();
  }
}
