package io.phasetwo.keycloak.magic.resources;

import com.j256.ormlite.jdbc.JdbcConnectionSource;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.jbosslog.JBossLog;
import org.keycloak.models.KeycloakSession;
import org.keycloak.services.resource.RealmResourceProvider;


@JBossLog
public class TinyUrlResourceProvider extends BaseRealmResourceProvider{

  private final KeycloakSession session;
  public TinyUrlResourceProvider(KeycloakSession session) {
    super(session);
    this.session = session;
  }

  @Override
  public Object getRealmResource() {
    TinyUrlResource tinyUrl = new TinyUrlResource(session);
    return tinyUrl;
  }

  @Override
  public void close() {

  }
}
