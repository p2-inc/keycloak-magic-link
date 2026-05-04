package io.phasetwo.keycloak.magic.resources;

import org.keycloak.models.KeycloakSession;

public class MagicLinkPublicResourceProvider extends BaseRealmResourceProvider {

  public MagicLinkPublicResourceProvider(KeycloakSession session) {
    super(session);
  }

  @Override
  public Object getRealmResource() {
    return new MagicLinkPublicResource(session);
  }
}
