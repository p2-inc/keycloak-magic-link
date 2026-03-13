package io.phasetwo.keycloak.magic.representation;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.Map;
import lombok.Data;

@Data
@JsonIgnoreProperties(ignoreUnknown = true)
public class MagicLinkV2Request {

  /** User's email address. Mutually exclusive with {@code username}. */
  @JsonProperty("email")
  private String email;

  /**
   * User's username. When provided, {@code force_create} is ignored (users are never
   * auto-created by username).
   */
  @JsonProperty("username")
  private String username;

  /** Client ID for which the OIDC authorization URL is built. */
  @JsonProperty("client_id")
  private String clientId;

  /** Token validity in seconds. Defaults to 300 (5 minutes). */
  @JsonProperty("expiration_seconds")
  private int expirationSeconds = 300;

  /**
   * Forces the resulting session to this LOA level. When set, {@link
   * io.phasetwo.keycloak.magic.auth.MagicLinkBFAuthenticator} writes this value directly into the
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
   * When {@code true} the token may be used multiple times until it expires. Default is
   * {@code false} (single-use).
   */
  @JsonProperty("reusable")
  private Boolean reusable = false;

  /**
   * Additional query parameters appended verbatim to the returned OIDC authorization URL. Use
   * this to pass {@code redirect_uri}, {@code scope}, {@code state}, {@code nonce},
   * {@code code_challenge}, {@code acr_values}, etc.
   */
  @JsonProperty("additional_parameters")
  private Map<String, String> additionalParameters;

  /**
   * When {@code true}, {@code user.setEmailVerified(true)} is called after the token is
   * successfully validated in the browser flow. Defaults to {@code false}.
   */
  @JsonProperty("set_email_verified")
  private Boolean setEmailVerified = false;
}
