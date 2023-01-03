package io.phasetwo.keycloak.magic.resources;

import org.jboss.resteasy.spi.ResteasyProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;

public class MagicLinkResourceProvider extends BaseRealmResourceProvider {

  public MagicLinkResourceProvider(KeycloakSession session) {
    super(session);
  }

  @Override
  public Object getRealmResource() {
    RealmModel realm = session.getContext().getRealm();
    MagicLinkResource magicLink = new MagicLinkResource(realm);
    ResteasyProviderFactory.getInstance().injectProperties(magicLink);
    magicLink.setup();
    return magicLink;
  }
}
