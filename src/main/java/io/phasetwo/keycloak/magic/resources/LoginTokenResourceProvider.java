package io.phasetwo.keycloak.magic.resources;

import org.keycloak.models.KeycloakSession;

public class LoginTokenResourceProvider extends BaseRealmResourceProvider {

  private final boolean legacyFormat;

  public LoginTokenResourceProvider(KeycloakSession session, boolean legacyFormat) {
    super(session);
    this.legacyFormat = legacyFormat;
  }

  @Override
  public Object getRealmResource() {
    LoginTokenResource resource = new LoginTokenResource(session, legacyFormat);
    resource.setup();
    return resource;
  }
}
