package io.phasetwo.keycloak.magic.resources;

import org.keycloak.models.KeycloakSession;

public class MagicLinkResourceProvider extends BaseRealmResourceProvider {

  public MagicLinkResourceProvider(KeycloakSession session) {
    super(session);
  }

  @Override
  public Object getRealmResource() {
    MagicLinkResource magicLink = new MagicLinkResource(session);
    magicLink.setup();
    return magicLink;
  }
}
