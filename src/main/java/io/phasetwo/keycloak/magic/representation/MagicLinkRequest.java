package io.phasetwo.keycloak.magic.representation;

import lombok.Data;

@Data
public class MagicLinkRequest {
  private String email;
  private String clientId;
  private String redirectUri;
  private int expirationSeconds = 60 * 60 * 24;
  private boolean forceCreate = false;
  private boolean sendEmail = false;
}
