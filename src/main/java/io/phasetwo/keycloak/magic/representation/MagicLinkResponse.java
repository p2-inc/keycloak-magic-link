package io.phasetwo.keycloak.magic.representation;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

@Data
public class MagicLinkResponse {
  @JsonProperty("user_id")
  private String userId;

  @JsonProperty("link")
  private String link;

  @JsonProperty("sent")
  private boolean sent;
}
