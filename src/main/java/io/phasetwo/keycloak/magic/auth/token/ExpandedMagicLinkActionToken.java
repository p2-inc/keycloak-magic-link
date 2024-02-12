package io.phasetwo.keycloak.magic.auth.token;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.UUID;
import org.keycloak.authentication.actiontoken.DefaultActionToken;

public class ExpandedMagicLinkActionToken extends DefaultActionToken {

  public static final String TOKEN_TYPE = "exp-magic-link";

  private static final String JSON_FIELD_REDIRECT_URI = "rdu";
  private static final String JSON_FIELD_SCOPE = "scope";
  private static final String JSON_FIELD_STATE = "state";
  private static final String JSON_FIELD_REMEMBER_ME = "rme";
  private static final String JSON_FIELD_STRING_NONCE = "nce";

  private static final String JSON_FIELD_REUSABLE = "ru";

  private static final String JSON_FIELD_SESSION_ID = "sid";
  private static final String JSON_FIELD_TAB_ID = "tid";

  @JsonProperty(value = JSON_FIELD_REDIRECT_URI)
  private String redirectUri;

  @JsonProperty(value = JSON_FIELD_SCOPE)
  private String scopes;

  @JsonProperty(value = JSON_FIELD_STATE)
  private String state;

  @JsonProperty(value = JSON_FIELD_REMEMBER_ME)
  private Boolean rememberMe = false;

  @JsonProperty(value = JSON_FIELD_REUSABLE)
  private Boolean actionTokenPersistent = true;

  @JsonProperty(value = JSON_FIELD_STRING_NONCE)
  private String nonce;

  @JsonProperty(value = JSON_FIELD_SESSION_ID)
  private String sessionId;

  @JsonProperty(value = JSON_FIELD_TAB_ID)
  private String tabId;

  public ExpandedMagicLinkActionToken(
      String userId,
      int absoluteExpirationInSecs,
      String clientId,
      String redirectUri,
      String scope,
      String nonce,
      String state,
      Boolean rememberMe,
      Boolean isActionTokenPersistent,
      String sessionId,
      String tabId) {
    super(userId, TOKEN_TYPE, absoluteExpirationInSecs, nonce(nonce));
    this.redirectUri = redirectUri;
    this.issuedFor = clientId;
    this.scopes = scope;
    this.state = state;
    this.rememberMe = rememberMe;
    this.actionTokenPersistent = isActionTokenPersistent;
    this.nonce = nonce;
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

  public String getRedirectUri() {
    return redirectUri;
  }

  public void setRedirectUri(String redirectUri) {
    this.redirectUri = redirectUri;
  }

  public String getScope() {
    return this.scopes;
  }

  public void setScope(String value) {
    this.scopes = value;
  }

  public String getState() {
    return this.state;
  }

  public void setState(String value) {
    this.state = value;
  }

  public Boolean getRememberMe() {
    return this.rememberMe;
  }

  public void setRememberMe(Boolean value) {
    this.rememberMe = value;
  }

  public Boolean getActionTokenPersistent() {
    return this.actionTokenPersistent;
  }

  public void setActionTokenPersistent(Boolean value) {
    this.actionTokenPersistent = value;
  }

  public String getNonce() {
    return this.nonce;
  }

  public void setNonce(String value) {
    this.nonce = value;
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
