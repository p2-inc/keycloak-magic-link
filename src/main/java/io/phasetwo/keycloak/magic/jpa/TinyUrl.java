package io.phasetwo.keycloak.magic.jpa;

import java.time.Instant;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.NamedQueries;
import javax.persistence.NamedQuery;
import javax.persistence.PrePersist;
import javax.persistence.Table;
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
  @NamedQuery(name = "findAllKeysOlderThan", query = "from TinyUrl where expiresAt < :time ")
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

  @PrePersist
  public void prePersist() {
    createdAt = Instant.now();
  }
}
