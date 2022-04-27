package io.phasetwo.keycloak.magic.resources;

import org.jboss.resteasy.spi.ResteasyProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.services.resource.RealmResourceProvider;

public class MagicLinkResourceProvider implements RealmResourceProvider {

  private final KeycloakSession session;

  public MagicLinkResourceProvider(KeycloakSession session) {
    this.session = session;
  }

  @Override
  public void close() {}

  @Override
  public Object getResource() {
    RealmModel realm = session.getContext().getRealm();
    MagicLinkResource magicLink = new MagicLinkResource(realm);
    ResteasyProviderFactory.getInstance().injectProperties(magicLink);
    magicLink.setup();
    return magicLink;
  }
}
