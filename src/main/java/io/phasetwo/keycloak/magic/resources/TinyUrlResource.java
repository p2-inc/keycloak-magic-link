package io.phasetwo.keycloak.magic.resources;

import io.phasetwo.keycloak.magic.jpa.TinyUrl;
import io.phasetwo.keycloak.magic.spi.TinyUrlService;
import io.phasetwo.keycloak.magic.spi.TinyUrlServiceProviderFactory;
import java.util.List;
import java.util.Optional;
import javax.persistence.EntityManager;
import javax.persistence.Query;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import lombok.extern.jbosslog.JBossLog;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.KeycloakSession;
import javax.ws.rs.core.MediaType;

@JBossLog
public class TinyUrlResource extends AbstractAdminResource {
  public TinyUrlResource(KeycloakSession session) {
    super(session);
  }

  @GET
  @Produces(MediaType.APPLICATION_JSON)
  @Path("{name}")
  public String validateTinyUrl(@PathParam("name") String name) {
    Optional<TinyUrl> tinyUrl = session.getProvider(TinyUrlService.class).findByUrlKey(name);
    return "Hello " + name + "! " + tinyUrl.isPresent();
  }


}
