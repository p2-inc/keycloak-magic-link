package io.phasetwo.keycloak.magic;

import io.phasetwo.keycloak.magic.auth.token.MagicLinkActionToken;
import io.phasetwo.keycloak.magic.constants.TinyUrlConstants;
import io.phasetwo.keycloak.magic.jpa.TinyUrl;
import io.phasetwo.keycloak.magic.representation.MagicLinkInfo;
import io.phasetwo.keycloak.magic.resources.TinyUrlResourceProviderFactory;
import io.phasetwo.keycloak.magic.spi.TinyUrlService;
import java.net.URI;
import java.time.Instant;
import java.util.Random;
import javax.ws.rs.core.UriInfo;
import lombok.extern.jbosslog.JBossLog;
import org.apache.commons.lang3.StringUtils;
import org.keycloak.models.Constants;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.services.Urls;

@JBossLog
public class TinyUrlHelper {

  public static MagicLinkInfo getTinyUri(
      KeycloakSession session, UriInfo uriInfo, MagicLinkActionToken token, RealmModel realm) {
    log.debugf(
        "baseUri: %s, token: %s, issuedFor: %s",
        uriInfo, token.serialize(session, realm, uriInfo), token.getIssuedFor());

    String urlKey = generateUrlKey(session, token, realm, uriInfo);
    log.debugf("urlKey: %s", urlKey);

    // This is for local env only
    if (StringUtils.isBlank(System.getenv(TinyUrlConstants.KC_ENV_KEY))) {
      String link =
          Urls.realmBase(uriInfo.getBaseUri())
              .path(session.getContext().getRealm().getName())
              .path(TinyUrlResourceProviderFactory.PROVIDER_ID)
              .path(urlKey)
              .build(session.getContext().getRealm().getName())
              .toString();
      return MagicLinkInfo.builder().link(link).code(urlKey).build();
    } else if (System.getenv(TinyUrlConstants.KC_ENV_KEY)
        .equals(TinyUrlConstants.KC_ENV_PROD_VALUE)) {
      String link =
          String.format(
              TinyUrlConstants.ESD_MAGIC_LINK_FORMAT,
              session.getContext().getClient().getRootUrl(),
              urlKey);
      return MagicLinkInfo.builder().link(link).code(urlKey).build();
    }
    throw new RuntimeException(
        "Invalid environment variable value for " + TinyUrlConstants.KC_ENV_KEY);

    //    return Urls.realmBase(baseUri)
    //        .path(session.getContext().getRealm().getName())
    //        .path(TinyUrlResourceProviderFactory.PROVIDER_ID)
    //        .path(urlKey);
  }

  public static String getActionTokenUri(URI baseUri, TinyUrl tinyUrl) {
    log.debugf("baseUri: %s, tokenString: %s", baseUri, tinyUrl.getJwtToken());
    return Urls.realmBase(baseUri)
        .path(tinyUrl.getRealmId())
        .path(TinyUrlConstants.ACTION_TOKEN_URL_PATH)
        .queryParam(Constants.KEY, tinyUrl.getJwtToken())
        .queryParam(Constants.CLIENT_ID, tinyUrl.getClientId())
        .build()
        .toString();
  }

  private static String generateUrlKey(
      KeycloakSession session, MagicLinkActionToken token, RealmModel realm, UriInfo uriInfo) {

    TinyUrlService tinyUrlService = session.getProvider(TinyUrlService.class);

    int foundUnique = TinyUrlConstants.NUMBER_OF_RETRIES_FOR_UNIQUE_URL_KEY;
    while (foundUnique-- > 0) {
      try {
        TinyUrl tinyUrl =
            TinyUrl.builder()
                .jwtToken(token.serialize(session, realm, uriInfo))
                .clientId(token.getIssuedFor())
                .urlKey(generateAlphanumericString())
                .realmId(session.getContext().getRealm().getName())
                .expiresAt(Instant.ofEpochSecond(token.getExp()))
                .email(session.users().getUserById(realm, token.getUserId()).getEmail())
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
