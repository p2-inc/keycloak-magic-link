package io.phasetwo.keycloak.magic.representation;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class MagicLinkInfo {
  @JsonProperty("link")
  private String link;

  @JsonProperty("code")
  private String code;
}
