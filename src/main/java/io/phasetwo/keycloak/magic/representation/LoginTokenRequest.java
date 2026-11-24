package io.phasetwo.keycloak.magic.representation;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

@Data
@JsonIgnoreProperties(ignoreUnknown = true)
public class LoginTokenRequest {

  /**
   * User's Keycloak ID. Takes precedence over {@code email} and {@code username} when provided.
   * {@code force_create} is ignored when this field is set.
   */
  @JsonProperty("user_id")
  private String userId;

  /** User's email address. Mutually exclusive with {@code username}. */
  @JsonProperty("email")
  private String email;

  /**
   * User's username. When provided, {@code force_create} is ignored (users are never
   * auto-created by username).
   */
  @JsonProperty("username")
  private String username;

  /**
   * Optional client ID the token is bound to. When set, redemption from any other client is
   * rejected — this binding is always enforced, regardless of authenticator configuration. When
   * omitted, an unbound ("universal") token is created that can be redeemed at any client, but
   * only by authenticator executions configured with "Client ID must match" = OFF. Unbound tokens
   * should use a short {@code expiration_seconds} and {@code reusable=false}.
   */
  @JsonProperty("client_id")
  private String clientId;

  /** Token validity in seconds. Defaults to 300 (5 minutes). */
  @JsonProperty("expiration_seconds")
  private int expirationSeconds = 300;

  /**
   * Forces the resulting session to this LOA level. When set, {@link
   * io.phasetwo.keycloak.magic.auth.LoginTokenVerifier} writes this value directly into the
   * AcrStore, overriding any level configured on a sibling {@code Condition - Level of
   * Authentication} in the browser flow.
   */
  @JsonProperty("loa")
  private Integer forceSessionLoa;

  /** Sets the remember-me flag on the authentication session. */
  @JsonProperty("remember_me")
  private Boolean rememberMe;

  /**
   * When {@code true} and the user does not exist, a new user account is created. Only applies
   * when {@code email} is provided; ignored when {@code username} is provided.
   */
  @JsonProperty("force_create")
  private boolean forceCreate = false;

  /**
   * Number of times the token may be redeemed until it expires: {@code 0} = unlimited, {@code 1} =
   * single use, up to {@link
   * io.phasetwo.keycloak.magic.auth.token.StatelessLoginToken#MAX_USES_LIMIT}. Takes precedence
   * over {@code reusable}. When neither is sent the token is unlimited.
   */
  @JsonProperty("max_uses")
  private Integer maxUses;

  /**
   * Legacy form of {@code max_uses}: {@code true} (the default when the field is omitted) =
   * unlimited, {@code false} or an explicit {@code null} = single use. Ignored when {@code
   * max_uses} is set.
   */
  @JsonProperty("reusable")
  private Boolean reusable = true;

  /**
   * Selects the token format. {@code false} issues a stateless (encrypted, self-contained) token;
   * {@code true} issues a token in the legacy format, whose credential is stored server-side. When
   * omitted, the server default applies (SPI option {@code legacy} of the {@code login-token}
   * realm resource, default {@code true}).
   */
  @JsonProperty("legacy")
  private Boolean legacy;

  /**
   * When {@code true}, {@code user.setEmailVerified(true)} is called after the token is
   * successfully validated in the browser flow. Defaults to {@code false}.
   */
  @JsonProperty("set_email_verified")
  private Boolean setEmailVerified = false;

  /**
   * When {@code true} and a different user is already logged in on the device, a confirmation
   * screen is shown asking the user to confirm the logout. When {@code false} (default), the
   * existing session is silently logged out and the login token is processed automatically.
   */
  @JsonProperty("confirm_user_switch")
  private Boolean confirmUserSwitch = false;
}
