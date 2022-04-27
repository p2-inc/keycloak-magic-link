package io.phasetwo.keycloak.magic.representation;

import lombok.Data;

@Data
public class MagicLinkResponse {
  private String userId;
  private String link;
  private boolean sent;
}
