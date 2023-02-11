package io.phasetwo.keycloak.magic.auth.token;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.keycloak.authentication.actiontoken.DefaultActionToken;

public class MagicLinkActionToken extends DefaultActionToken {

  public static final String TOKEN_TYPE = "ext-magic-link";

  private static final String JSON_FIELD_REDIRECT_URI = "rdu";
  private static final String JSON_FIELD_SCOPE = "scope";

  @JsonProperty(value = JSON_FIELD_REDIRECT_URI)
  private String redirectUri;

  @JsonProperty(value = JSON_FIELD_SCOPE)
  private String scopes;

  public MagicLinkActionToken(
      String userId, int absoluteExpirationInSecs, String clientId, String redirectUri, String scope) {
    super(userId, TOKEN_TYPE, absoluteExpirationInSecs, null);
    this.redirectUri = redirectUri;
    this.issuedFor = clientId;
    this.scopes = scope;
  }

  private MagicLinkActionToken() {
    // Note that the class must have a private constructor without any arguments. This is necessary
    // to deserialize the token class from JWT.
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
}
