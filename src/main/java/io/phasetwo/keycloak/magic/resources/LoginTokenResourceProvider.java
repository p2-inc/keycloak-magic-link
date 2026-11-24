package io.phasetwo.keycloak.magic.resources;

import org.keycloak.models.KeycloakSession;

public class LoginTokenResourceProvider extends BaseRealmResourceProvider {

  private final boolean statelessByDefault;

  public LoginTokenResourceProvider(KeycloakSession session, boolean statelessByDefault) {
    super(session);
    this.statelessByDefault = statelessByDefault;
  }

  @Override
  public Object getRealmResource() {
    LoginTokenResource resource = new LoginTokenResource(session, statelessByDefault);
    resource.setup();
    return resource;
  }
}
