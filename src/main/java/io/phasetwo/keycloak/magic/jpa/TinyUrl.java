package io.phasetwo.keycloak.magic.jpa;

import java.time.Instant;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.NamedQueries;
import jakarta.persistence.NamedQuery;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
@Table(name = "tiny_url")
@NamedQueries({
  @NamedQuery(
      name = "findByUrlKey",
      query = "from TinyUrl where urlKey = :urlKey and realmId = :realmId"),
  @NamedQuery(
      name = "findAllKeysExpiredBeforeAndNotDeleted",
      query = "from TinyUrl where expiresAt < :time and deleted = false"),
  @NamedQuery(name = "findAllKeysExpiredBefore", query = "from TinyUrl where expiresAt < :time ")
})
public class TinyUrl {

  @Id
  @Column(name = "id")
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private long id;

  @Column(name = "realm_id", nullable = false)
  private String realmId;

  @Column(name = "url_key", nullable = false)
  private String urlKey;

  @Column(name = "jwt_token", nullable = false)
  private String jwtToken;

  @Column(name = "client_id", nullable = false)
  private String clientId;

  @Column(name = "created_at", nullable = false)
  private Instant createdAt;

  @Column(name = "expires_at", nullable = false)
  private Instant expiresAt;

  @Column(name = "email")
  private String email;

  @Column(name = "deleted", nullable = false)
  private boolean deleted;

  @PrePersist
  public void prePersist() {
    createdAt = Instant.now();
    deleted = false;
  }
}
