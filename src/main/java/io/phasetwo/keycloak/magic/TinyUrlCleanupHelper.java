package io.phasetwo.keycloak.magic;

import io.phasetwo.keycloak.magic.constants.TinyUrlConstants;
import io.phasetwo.keycloak.magic.jpa.TinyUrl;
import io.phasetwo.keycloak.magic.spi.TinyUrlService;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import lombok.NoArgsConstructor;
import lombok.extern.jbosslog.JBossLog;
import org.keycloak.models.KeycloakSession;

@JBossLog
@NoArgsConstructor
public class TinyUrlCleanupHelper {

  public static void cleanupOldUrlkeys(KeycloakSession session) {
    TinyUrlService tinyUrlService = session.getProvider(TinyUrlService.class);

    // Urls to soft delete
    List<TinyUrl> tinyUrls =
        tinyUrlService.findAllKeysExpiredBeforeAndNotDeleted(Instant.now().getEpochSecond());
    tinyUrls.forEach(tinyUrlService::softDeleteTinyUrl);
    log.infof("Soft Deleted %d old Tiny Urls", tinyUrls.size());

    // Urls to hard delete
    tinyUrls =
        tinyUrlService.findAllKeysExpiredBefore(
            Instant.now()
                .minus(TinyUrlConstants.TINY_URL_HARD_DELETE_DAYS, ChronoUnit.DAYS)
                .getEpochSecond());
    tinyUrls.forEach(tinyUrlService::hardDeleteTinyUrl);
    log.infof("Hard Deleted %d old Tiny Urls", tinyUrls.size());
  }
}
