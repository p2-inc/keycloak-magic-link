package io.phasetwo.keycloak.magic.representation;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

@Data
public class MagicLinkV2Response {

  /**
   * The {@code login_hint} value to pass verbatim to the OIDC authorization endpoint,
   * e.g. {@code mlv2:5713e2a7-53a6-4fbc-8ff5-53d5d8862418}.
   *
   * <p>The caller is responsible for constructing the full OIDC authorization URL and must
   * include {@code prompt=login} to prevent Keycloak from short-circuiting the flow with an
   * existing session belonging to a different user.
   */
  @JsonProperty("login_hint")
  private String loginHint;
}
