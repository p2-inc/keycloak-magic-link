package io.phasetwo.keycloak.magic;

import io.phasetwo.keycloak.magic.resources.TinyUrlResource;
import java.net.URI;
import javax.ws.rs.core.UriBuilder;
import lombok.extern.jbosslog.JBossLog;
import org.keycloak.models.Constants;
import org.keycloak.services.Urls;
import org.keycloak.services.resources.LoginActionsService;
import org.keycloak.services.resources.RealmsResource;

@JBossLog
public class TinyUrl {

  public static UriBuilder tinyUrlBuilder(URI baseUri, String urlKey) {
    log.infof("baseUri: %s, urlKey: %s", baseUri, urlKey);
    return Urls.realmBase(baseUri)
        .path(TinyUrlResource.class, "getLoginActionsService")
        .path(LoginActionsService.class, "validateTinyUrl").path(urlKey);

  }
}
