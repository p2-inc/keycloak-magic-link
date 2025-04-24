package io.phasetwo.keycloak.magic.representation;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

@Data
@JsonIgnoreProperties(ignoreUnknown = true)
public class MagicLinkContinuationRequest {
  @JsonProperty("sessionId")
  private String sessionId;
}
