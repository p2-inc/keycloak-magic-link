package io.phasetwo.keycloak.magic.auth.token;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.UUID;
import org.keycloak.authentication.actiontoken.DefaultActionToken;

public class ExpandedMagicLinkActionToken extends DefaultActionToken {

  public static final String TOKEN_TYPE = "exp-magic-link";

  private static final String JSON_FIELD_SESSION_ID = "sid";
  private static final String JSON_FIELD_TAB_ID = "tid";

  @JsonProperty(value = JSON_FIELD_SESSION_ID)
  private String sessionId;

  @JsonProperty(value = JSON_FIELD_TAB_ID)
  private String tabId;

  public ExpandedMagicLinkActionToken(
      String userId,
      int absoluteExpirationInSecs,
      String clientId,
      String nonce,
      String sessionId,
      String tabId) {
    super(userId, TOKEN_TYPE, absoluteExpirationInSecs, nonce(nonce));
    this.issuedFor = clientId;
    this.sessionId = sessionId;
    this.tabId = tabId;
  }

  private ExpandedMagicLinkActionToken() {
    // Note that the class must have a private constructor without any arguments. This is necessary
    // to deserialize the token class from JWT.
  }

  static UUID nonce(String nonce) {
    try {
      return UUID.fromString(nonce);
    } catch (Exception ignore) {
    }
    return null;
  }

  public String getSessionId() {
    return sessionId;
  }

  public void setSessionId(String sessionId) {
    this.sessionId = sessionId;
  }

  public String getTabId() {
    return tabId;
  }

  public void setTabId(String tabId) {
    this.tabId = tabId;
  }
}
