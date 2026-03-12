package io.phasetwo.keycloak.magic.representation;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

@Data
@JsonIgnoreProperties(ignoreUnknown = true)
public class MagicLinkRequest {
  @JsonProperty("username")
  private String username;

  @JsonProperty("email")
  private String email;

  @JsonProperty("client_id")
  private String clientId;

  @JsonProperty("redirect_uri")
  private String redirectUri;

  @JsonProperty("expiration_seconds")
  private int expirationSeconds = 60 * 60 * 24;

  @JsonProperty("force_create")
  private boolean forceCreate = false;

  @JsonProperty("update_profile")
  private boolean updateProfile = false;

  @JsonProperty("update_password")
  private boolean updatePassword = false;

  @JsonProperty("send_email")
  private boolean sendEmail = false;

  @JsonProperty("scope")
  private String scope = null;

  @JsonProperty("nonce")
  private String nonce = null;

  @JsonProperty("state")
  private String state = null;

  @JsonProperty("code_challenge")
  private String codeChallenge = null;

  @JsonProperty("code_challenge_method")
  private String codeChallengeMethod = null;

  @JsonProperty("remember_me")
  private Boolean rememberMe = false;

  @JsonProperty("reusable")
  private Boolean actionTokenPersistent = true;

  @JsonProperty("response_mode")
  private String responseMode = null;

  /**
   * Forces the resulting session to receive the provided Level of Authentication. This value is
   * set directly in the AcrStore and ignores the level configured on the
   * {@code Condition - Level of Authentication} in the browser flow.
   */
  @JsonProperty("loa")
  private Integer forceSessionLoa = null;

  /**
   * Requested ACR values (space-separated). Works exactly like {@code acr_values} in a normal
   * OIDC authorization request: the browser flow's {@code Condition - Level of Authentication}
   * steps evaluate which levels need to run based on this value.
   */
  @JsonProperty("acr_values")
  private String acrValues = null;
}
