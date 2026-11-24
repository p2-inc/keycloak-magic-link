package io.phasetwo.keycloak.magic.resources;

import org.keycloak.models.KeycloakSession;

public class LoginTokenResourceProvider extends BaseRealmResourceProvider {

  private final boolean legacyByDefault;

  public LoginTokenResourceProvider(KeycloakSession session, boolean legacyByDefault) {
    super(session);
    this.legacyByDefault = legacyByDefault;
  }

  @Override
  public Object getRealmResource() {
    LoginTokenResource resource = new LoginTokenResource(session, legacyByDefault);
    resource.setup();
    return resource;
  }
}
