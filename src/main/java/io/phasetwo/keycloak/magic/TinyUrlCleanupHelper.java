package io.phasetwo.keycloak.magic;

import io.phasetwo.keycloak.magic.jpa.TinyUrl;
import io.phasetwo.keycloak.magic.spi.TinyUrlService;
import java.time.Instant;
import java.util.List;
import lombok.NoArgsConstructor;
import lombok.extern.jbosslog.JBossLog;
import org.keycloak.models.KeycloakSession;

@JBossLog
@NoArgsConstructor
public class TinyUrlCleanupHelper {

  public static void cleanupOldUrlkeys(KeycloakSession session) {
    TinyUrlService tinyUrlService = session.getProvider(TinyUrlService.class);

    List<TinyUrl> tinyUrls = tinyUrlService.findAllKeysOlderThan(Instant.now().getEpochSecond());
    tinyUrls.forEach(tinyUrlService::hardDeleteTinyUrl);
    log.infof("Deleted %d old Tiny Urls", tinyUrls.size());

  }
}
