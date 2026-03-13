package io.phasetwo.keycloak.magic.resources;

import org.keycloak.models.KeycloakSession;

public class MagicLinkV2ResourceProvider extends BaseRealmResourceProvider {

  public MagicLinkV2ResourceProvider(KeycloakSession session) {
    super(session);
  }

  @Override
  public Object getRealmResource() {
    MagicLinkV2Resource resource = new MagicLinkV2Resource(session);
    resource.setup();
    return resource;
  }
}
