package io.phasetwo.keycloak.magic.auth.token;

import com.fasterxml.jackson.annotation.JsonProperty;

public class BoundMagicLinkActionToken extends MagicLinkActionToken {

  private static final String JSON_FIELD_COOKIE_SID = "csid";
  private static final String JSON_FIELD_IP = "ip";
  private static final String JSON_FIELD_UA = "ua";

  @JsonProperty(value = JSON_FIELD_COOKIE_SID)
  private String cookieSid;  // same-browser proof

  @JsonProperty(value = JSON_FIELD_IP)
  private String ip;

  @JsonProperty(value = JSON_FIELD_UA)
  private String ua;

  public BoundMagicLinkActionToken(
      String userId,
      int absoluteExpirationInSecs,
      String clientId,
      String redirectUri,
      String cookieSid,
      String ip,
      String ua) {
    super(userId, absoluteExpirationInSecs, clientId, redirectUri);
    this.cookieSid = cookieSid;
    this.ip = ip;
    this.ua = ua;
  }

  public BoundMagicLinkActionToken(
      String userId,
      int absoluteExpirationInSecs,
      String clientId,
      String redirectUri,
      String scope,
      String nonce,
      String state,
      String cookieSid,
      String ip,
      String ua) {
    super(userId, absoluteExpirationInSecs, clientId, redirectUri, scope, nonce, state);
    this.cookieSid = cookieSid;
    this.ip = ip;
    this.ua = ua;
  }

  public BoundMagicLinkActionToken(
      String userId,
      int absoluteExpirationInSecs,
      String clientId,
      String redirectUri,
      String scope,
      String nonce,
      String state,
      Boolean rememberMe,
      Boolean isActionTokenPersistent,
      String cookieSid,
      String ip,
      String ua) {
    super(userId, absoluteExpirationInSecs, clientId, redirectUri, scope, nonce, state, rememberMe, isActionTokenPersistent);
    this.cookieSid = cookieSid;
    this.ip = ip;
    this.ua = ua;
  }

  public BoundMagicLinkActionToken(
      String userId,
      int absoluteExpirationInSecs,
      String clientId,
      String redirectUri,
      String scope,
      String nonce,
      String state,
      String codeChallenge,
      String codeChallengeMethod,
      Boolean rememberMe,
      Boolean isActionTokenPersistent,
      String cookieSid,
      String ip,
      String ua) {
    super(userId, absoluteExpirationInSecs, clientId, redirectUri, scope, nonce, state, codeChallenge, codeChallengeMethod, rememberMe, isActionTokenPersistent);
    this.cookieSid = cookieSid;
    this.ip = ip;
    this.ua = ua;
  }

  private BoundMagicLinkActionToken() {
    // Required for deserialization
  }

  public String getCookieSid() {
    return cookieSid;
  }

  public void setCookieSid(String cookieSid) {
    this.cookieSid = cookieSid;
  }

  public String getIp() {
    return ip;
  }

  public void setIp(String ip) {
    this.ip = ip;
  }

  public String getUa() {
    return ua;
  }

  public void setUa(String ua) {
    this.ua = ua;
  }
}
