package io.phasetwo.keycloak.magic.representation;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

@Data
public class MagicLinkV2Response {

  /**
   * The OIDC authorization URL containing the magic-link credential in {@code login_hint}.
   * Append additional OIDC parameters ({@code redirect_uri}, {@code scope}, {@code state}, etc.)
   * if they were not already supplied via {@code additional_parameters} in the request.
   */
  @JsonProperty("link")
  private String link;

  /** The resolved user ID. */
  @JsonProperty("user_id")
  private String userId;
}
