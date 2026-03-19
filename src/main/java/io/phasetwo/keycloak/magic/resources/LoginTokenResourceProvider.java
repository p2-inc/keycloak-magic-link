package io.phasetwo.keycloak.magic.resources;

import org.keycloak.models.KeycloakSession;

public class LoginTokenResourceProvider extends BaseRealmResourceProvider {

  public LoginTokenResourceProvider(KeycloakSession session) {
    super(session);
  }

  @Override
  public Object getRealmResource() {
    LoginTokenResource resource = new LoginTokenResource(session);
    resource.setup();
    return resource;
  }
}
