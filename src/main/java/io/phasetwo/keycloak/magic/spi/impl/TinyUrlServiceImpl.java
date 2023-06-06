package io.phasetwo.keycloak.magic.spi.impl;

import io.phasetwo.keycloak.magic.jpa.TinyUrl;
import io.phasetwo.keycloak.magic.spi.TinyUrlService;
import java.util.List;
import java.util.Optional;
import javax.persistence.EntityManager;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;

public class TinyUrlServiceImpl implements TinyUrlService {

  private final KeycloakSession session;

  public TinyUrlServiceImpl(KeycloakSession session) {
    this.session = session;
    RealmModel realm = getRealm();
    if (getRealm() == null) {
      throw new IllegalStateException("The service cannot accept a session without a realm in its context.");
    }
  }

  @Override
  public Optional<TinyUrl> findByUrlKey( String urlKey) {
    List<TinyUrl> tinyUrls = getEntityManager().createNamedQuery("findByUrlKey", TinyUrl.class)
        .setParameter("urlKey", urlKey)
        .setParameter("realmId", getRealm().getId())
        .getResultList();
    return Optional.ofNullable(tinyUrls.size() > 0 ? tinyUrls.get(0) : null);
  }

  @Override
  public void close() {

  }

  private RealmModel getRealm() {
    return session.getContext().getRealm();
  }

  private EntityManager getEntityManager() {
    return session.getProvider(JpaConnectionProvider.class).getEntityManager();
  }

}
