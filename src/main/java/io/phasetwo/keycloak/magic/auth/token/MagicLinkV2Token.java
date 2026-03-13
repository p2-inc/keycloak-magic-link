package io.phasetwo.keycloak.magic.auth.token;

/**
 * Data carrier for Magic Link v2 credentials.
 *
 * <p>Instances are stored in {@link org.keycloak.models.SingleUseObjectProvider} at generation
 * time; only a short UUID reference ({@code mlv2:{uuid}}) is placed in the OIDC
 * {@code login_hint} parameter to stay within Keycloak's 255-character limit.
 *
 * <p>Fields stored:
 * <ul>
 *   <li>{@code userId}     — subject (user ID)</li>
 *   <li>{@code clientId}   — intended OIDC client</li>
 *   <li>{@code expiry}     — absolute expiry (Unix epoch seconds)</li>
 *   <li>{@code loa}        — optional forced session LOA level</li>
 *   <li>{@code rememberMe} — whether to set the remember-me flag</li>
 *   <li>{@code reusable}   — whether the token may be redeemed more than once</li>
 *   <li>{@code sev}        — whether to mark the user's email as verified on redemption</li>
 * </ul>
 */
public class MagicLinkV2Token {

  // Map keys used in SingleUseObjectProvider notes
  public static final String KEY_USER_ID      = "userId";
  public static final String KEY_CLIENT_ID    = "clientId";
  public static final String KEY_EXPIRY       = "expiry";
  public static final String KEY_LOA          = "loa";
  public static final String KEY_REMEMBER_ME         = "rememberMe";
  public static final String KEY_REUSABLE            = "reusable";
  public static final String KEY_SEV                 = "sev";
  /**
   * When {@code "true"}, show the user-switch confirmation form instead of performing an automatic
   * logout. Default (absent / {@code "false"}) is auto-logout.
   */
  public static final String KEY_CONFIRM_USER_SWITCH = "confirmUserSwitch";

  private String userId;
  private String clientId;
  private long expiry;
  private Integer forceSessionLoa;
  private Boolean rememberMe;
  private Boolean reusable;
  private Boolean setEmailVerified;

  public String getUserId() { return userId; }
  public void setUserId(String userId) { this.userId = userId; }

  public String getClientId() { return clientId; }
  public void setClientId(String clientId) { this.clientId = clientId; }

  public long getExpiry() { return expiry; }
  public void setExpiry(long expiry) { this.expiry = expiry; }

  public Integer getForceSessionLoa() { return forceSessionLoa; }
  public void setForceSessionLoa(Integer forceSessionLoa) { this.forceSessionLoa = forceSessionLoa; }

  public Boolean getRememberMe() { return rememberMe; }
  public void setRememberMe(Boolean rememberMe) { this.rememberMe = rememberMe; }

  public Boolean getReusable() { return reusable; }
  public void setReusable(Boolean reusable) { this.reusable = reusable; }

  public Boolean getSetEmailVerified() { return setEmailVerified; }
  public void setSetEmailVerified(Boolean setEmailVerified) { this.setEmailVerified = setEmailVerified; }
}
