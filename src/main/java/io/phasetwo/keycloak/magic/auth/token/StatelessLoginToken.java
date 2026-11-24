package io.phasetwo.keycloak.magic.auth.token;

import static io.phasetwo.keycloak.magic.auth.token.LoginToken.KEY_CLIENT_ID;
import static io.phasetwo.keycloak.magic.auth.token.LoginToken.KEY_CONFIRM_USER_SWITCH;
import static io.phasetwo.keycloak.magic.auth.token.LoginToken.KEY_EXPIRY;
import static io.phasetwo.keycloak.magic.auth.token.LoginToken.KEY_LOA;
import static io.phasetwo.keycloak.magic.auth.token.LoginToken.KEY_MAX_USES;
import static io.phasetwo.keycloak.magic.auth.token.LoginToken.KEY_REMEMBER_ME;
import static io.phasetwo.keycloak.magic.auth.token.LoginToken.KEY_SEV;
import static io.phasetwo.keycloak.magic.auth.token.LoginToken.KEY_USER_ID;

import java.io.ByteArrayOutputStream;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.regex.Pattern;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Self-contained ("stateless") Login Token: the credential travels inside the token, encrypted and
 * authenticated with AES-GCM, instead of being stored server-side at creation time.
 *
 * <p>Wire format of the token id (the part after the {@code lt:} login-hint prefix):
 *
 * <pre>
 *   v2.&lt;base64url( salt[16] || ciphertext || tag[16] )&gt;
 * </pre>
 *
 * <p><b>One key per token.</b> The realm key is never used for encryption directly. For every
 * token a fresh 16-byte random salt is drawn and {@code HMAC-SHA512(realmKey, context || salt)}
 * yields a 256-bit AES key and a 96-bit GCM nonce used for that token only. AES-GCM limits how
 * many messages one key may encrypt with random nonces (about 2<sup>32</sup>); deriving a key per
 * token removes that limit, so the realm key does not have to be rotated because of the number of
 * tokens issued.
 *
 * <p>The realm id is bound as additional authenticated data, so a token is only accepted by the
 * realm that issued it. The salt doubles as the token's identity for use counting — see {@link
 * Payload#getUseId()}.
 *
 * <p>Plaintext layout (kept binary so the login hint stays well below Keycloak's 255-character
 * {@code login_hint} limit):
 *
 * <pre>
 *   flags[1] maxUses[1] expiry[4] issuedAt[4] [loa[1]] userId [clientId]
 * </pre>
 *
 * Times are unsigned epoch seconds. A canonical UUID is written as 16 raw bytes; any other id is
 * written as a length byte followed by its UTF-8 bytes.
 */
public final class StatelessLoginToken {

  /** Token-id prefix that distinguishes a stateless token from a legacy {@code {uuid}} token. */
  public static final String PREFIX = "v2.";

  /** Keycloak's default maximum length of the OIDC {@code login_hint} parameter. */
  public static final int MAX_LOGIN_HINT_LENGTH = 255;

  /** Highest supported use limit; {@code 0} means unlimited. */
  public static final int MAX_USES_LIMIT = 10;

  private static final String CIPHER = "AES/GCM/NoPadding";
  private static final String KDF = "HmacSHA512";
  private static final int SALT_LENGTH = 16;

  /** Leading base64 characters that encode salt bits only (21 * 6 = 126 of its 128 bits). */
  private static final int SALT_LOG_LENGTH = 21;

  private static final int KEY_LENGTH = 32;
  private static final int NONCE_LENGTH = 12;
  private static final int TAG_LENGTH = 16;
  private static final String AAD_PREFIX = "keycloak-login-token:v2:";
  private static final byte[] KDF_CONTEXT =
      "keycloak-login-token:v2:token-key:".getBytes(StandardCharsets.UTF_8);
  private static final Pattern LEGACY_TOKEN_ID =
      Pattern.compile("[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}");

  private static final int FLAG_REMEMBER_ME = 1;
  private static final int FLAG_SET_EMAIL_VERIFIED = 1 << 1;
  private static final int FLAG_CONFIRM_USER_SWITCH = 1 << 2;
  private static final int FLAG_HAS_LOA = 1 << 3;
  private static final int FLAG_HAS_CLIENT = 1 << 4;
  private static final int FLAG_USER_ID_IS_UUID = 1 << 5;

  private static final long MAX_EXPIRY = 0xFFFFFFFFL;
  private static final SecureRandom RANDOM = new SecureRandom();

  private StatelessLoginToken() {}

  /** Decrypted content of a stateless Login Token. */
  public static final class Payload {
    private String userId;
    private String clientId;
    private long expiry;
    private long issuedAt;
    private Integer loa;
    private int maxUses;
    private boolean rememberMe;
    private boolean setEmailVerified;
    private boolean confirmUserSwitch;
    private String useId;

    public String getUserId() {
      return userId;
    }

    public Payload setUserId(String userId) {
      this.userId = userId;
      return this;
    }

    public String getClientId() {
      return clientId;
    }

    public Payload setClientId(String clientId) {
      this.clientId = clientId;
      return this;
    }

    /** Absolute expiry in epoch seconds. */
    public long getExpiry() {
      return expiry;
    }

    public Payload setExpiry(long expiry) {
      this.expiry = expiry;
      return this;
    }

    /** Time the token was issued, in epoch seconds. */
    public long getIssuedAt() {
      return issuedAt;
    }

    public Payload setIssuedAt(long issuedAt) {
      this.issuedAt = issuedAt;
      return this;
    }

    public Integer getLoa() {
      return loa;
    }

    public Payload setLoa(Integer loa) {
      this.loa = loa;
      return this;
    }

    /** Number of allowed redemptions; {@code 0} means unlimited. */
    public int getMaxUses() {
      return maxUses;
    }

    public Payload setMaxUses(int maxUses) {
      this.maxUses = maxUses;
      return this;
    }

    public boolean isRememberMe() {
      return rememberMe;
    }

    public Payload setRememberMe(boolean rememberMe) {
      this.rememberMe = rememberMe;
      return this;
    }

    public boolean isSetEmailVerified() {
      return setEmailVerified;
    }

    public Payload setSetEmailVerified(boolean setEmailVerified) {
      this.setEmailVerified = setEmailVerified;
      return this;
    }

    public boolean isConfirmUserSwitch() {
      return confirmUserSwitch;
    }

    public Payload setConfirmUserSwitch(boolean confirmUserSwitch) {
      this.confirmUserSwitch = confirmUserSwitch;
      return this;
    }

    /**
     * Identity of this token for use counting: the base64url-encoded salt. Only set on payloads
     * returned by {@link #open}.
     */
    public String getUseId() {
      return useId;
    }

    /**
     * Converts the payload into the same notes map a legacy Login Token carries, so both token
     * kinds share one verification pipeline.
     */
    public Map<String, String> toNotes() {
      Map<String, String> notes = new HashMap<>();
      notes.put(KEY_USER_ID, userId);
      if (clientId != null) {
        notes.put(KEY_CLIENT_ID, clientId);
      }
      notes.put(KEY_EXPIRY, String.valueOf(expiry));
      notes.put(KEY_MAX_USES, String.valueOf(maxUses));
      if (loa != null) {
        notes.put(KEY_LOA, String.valueOf(loa));
      }
      if (rememberMe) {
        notes.put(KEY_REMEMBER_ME, "true");
      }
      if (setEmailVerified) {
        notes.put(KEY_SEV, "true");
      }
      if (confirmUserSwitch) {
        notes.put(KEY_CONFIRM_USER_SWITCH, "true");
      }
      return notes;
    }
  }

  /** Returns {@code true} if the token id (without the {@code lt:} prefix) is a stateless token. */
  public static boolean isStateless(String tokenId) {
    return tokenId != null && tokenId.startsWith(PREFIX);
  }

  /**
   * Returns {@code true} if the token id has the shape of a legacy token: a UUID. Anything else is
   * not a token this plugin ever issued and must not be used as a key in the single-use store —
   * Keycloak reserves parts of that key space (for example keys ending in {@code .revoked}) and
   * answers lookups there with an exception.
   */
  public static boolean isLegacy(String tokenId) {
    return tokenId != null && LEGACY_TOKEN_ID.matcher(tokenId).matches();
  }

  /**
   * Returns a value that identifies the token in log output without revealing the credential. Both
   * token kinds are bearer credentials, so neither is ever logged in full: a stateless token is
   * reduced to its salt (which is also its use-counting id), a legacy UUID to its first block, and
   * anything else — a mistyped or doubly prefixed token may still contain a valid one — to its
   * length.
   */
  public static String logId(String tokenId) {
    if (tokenId == null) {
      return "<none>";
    }
    if (isStateless(tokenId)) {
      String body = tokenId.substring(PREFIX.length());
      if (body.length() > SALT_LOG_LENGTH && body.matches("[A-Za-z0-9_-]+=*")) {
        return "v2:" + body.substring(0, SALT_LOG_LENGTH);
      }
    } else if (isLegacy(tokenId)) {
      return tokenId.substring(0, 8) + "…";
    }
    return "<malformed:" + tokenId.length() + ">";
  }

  /**
   * Encrypts the payload into a token id ({@code v2.…}).
   *
   * @throws IllegalArgumentException if a field cannot be represented in the compact format (for
   *     example an id longer than 255 bytes); callers fall back to a legacy token.
   */
  public static String seal(SecretKey key, String realmId, Payload payload) {
    byte[] plaintext = encode(payload);
    byte[] salt = new byte[SALT_LENGTH];
    RANDOM.nextBytes(salt);
    try {
      Cipher cipher = tokenCipher(Cipher.ENCRYPT_MODE, key, salt);
      cipher.updateAAD(aad(realmId));
      byte[] ciphertext = cipher.doFinal(plaintext);
      byte[] token = new byte[SALT_LENGTH + ciphertext.length];
      System.arraycopy(salt, 0, token, 0, SALT_LENGTH);
      System.arraycopy(ciphertext, 0, token, SALT_LENGTH, ciphertext.length);
      return PREFIX + Base64.getUrlEncoder().withoutPadding().encodeToString(token);
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException("Failed to encrypt login token", e);
    }
  }

  /**
   * Decrypts a token id with the first of the given keys that authenticates it.
   *
   * @return the payload, or empty if the token is malformed, was tampered with, belongs to another
   *     realm, or was encrypted with a key that is no longer available. Expiry is <em>not</em>
   *     checked here.
   */
  public static Optional<Payload> open(Collection<SecretKey> keys, String realmId, String tokenId) {
    if (!isStateless(tokenId)) {
      return Optional.empty();
    }
    byte[] token;
    try {
      token = Base64.getUrlDecoder().decode(tokenId.substring(PREFIX.length()));
    } catch (IllegalArgumentException e) {
      return Optional.empty();
    }
    if (token.length <= SALT_LENGTH + TAG_LENGTH) {
      return Optional.empty();
    }
    for (SecretKey key : keys) {
      byte[] plaintext = decrypt(key, realmId, token);
      if (plaintext == null) {
        continue;
      }
      try {
        Payload payload = decode(plaintext);
        payload.useId =
            Base64.getUrlEncoder().withoutPadding().encodeToString(slice(token, 0, SALT_LENGTH));
        return Optional.of(payload);
      } catch (BufferUnderflowException | IllegalArgumentException e) {
        return Optional.empty();
      }
    }
    return Optional.empty();
  }

  private static byte[] decrypt(SecretKey key, String realmId, byte[] token) {
    try {
      Cipher cipher = tokenCipher(Cipher.DECRYPT_MODE, key, slice(token, 0, SALT_LENGTH));
      cipher.updateAAD(aad(realmId));
      return cipher.doFinal(token, SALT_LENGTH, token.length - SALT_LENGTH);
    } catch (GeneralSecurityException e) {
      // Wrong key, wrong realm or a modified token: indistinguishable by design.
      return null;
    }
  }

  /**
   * Derives the AES key and GCM nonce that belong to this token alone and returns a cipher
   * initialised with them. Because the pair is a function of the realm key and a 128-bit random
   * salt, no key/nonce pair is ever used for two tokens.
   */
  private static Cipher tokenCipher(int mode, SecretKey realmKey, byte[] salt)
      throws GeneralSecurityException {
    Mac mac = Mac.getInstance(KDF);
    mac.init(new SecretKeySpec(realmKey.getEncoded(), KDF));
    mac.update(KDF_CONTEXT);
    byte[] derived = mac.doFinal(salt);
    Cipher cipher = Cipher.getInstance(CIPHER);
    cipher.init(
        mode,
        new SecretKeySpec(derived, 0, KEY_LENGTH, "AES"),
        new GCMParameterSpec(TAG_LENGTH * 8, derived, KEY_LENGTH, NONCE_LENGTH));
    return cipher;
  }

  private static byte[] aad(String realmId) {
    return (AAD_PREFIX + realmId).getBytes(StandardCharsets.UTF_8);
  }

  private static byte[] encode(Payload p) {
    if (p.userId == null || p.userId.isEmpty()) {
      throw new IllegalArgumentException("userId is required");
    }
    if (p.expiry < 0 || p.expiry > MAX_EXPIRY) {
      throw new IllegalArgumentException("expiry out of range");
    }
    if (p.issuedAt < 0 || p.issuedAt > MAX_EXPIRY) {
      throw new IllegalArgumentException("issuedAt out of range");
    }
    if (p.maxUses < 0 || p.maxUses > MAX_USES_LIMIT) {
      throw new IllegalArgumentException("maxUses out of range");
    }
    if (p.loa != null && (p.loa < 0 || p.loa > Byte.MAX_VALUE)) {
      throw new IllegalArgumentException("loa out of range");
    }
    UUID userUuid = canonicalUuid(p.userId);

    int flags = 0;
    if (p.rememberMe) flags |= FLAG_REMEMBER_ME;
    if (p.setEmailVerified) flags |= FLAG_SET_EMAIL_VERIFIED;
    if (p.confirmUserSwitch) flags |= FLAG_CONFIRM_USER_SWITCH;
    if (p.loa != null) flags |= FLAG_HAS_LOA;
    if (p.clientId != null) flags |= FLAG_HAS_CLIENT;
    if (userUuid != null) flags |= FLAG_USER_ID_IS_UUID;

    ByteArrayOutputStream out = new ByteArrayOutputStream(64);
    out.write(flags);
    out.write(p.maxUses);
    out.writeBytes(ByteBuffer.allocate(8).putInt((int) p.expiry).putInt((int) p.issuedAt).array());
    if (p.loa != null) {
      out.write(p.loa);
    }
    if (userUuid != null) {
      out.writeBytes(
          ByteBuffer.allocate(16)
              .putLong(userUuid.getMostSignificantBits())
              .putLong(userUuid.getLeastSignificantBits())
              .array());
    } else {
      writeString(out, p.userId);
    }
    if (p.clientId != null) {
      writeString(out, p.clientId);
    }
    return out.toByteArray();
  }

  private static Payload decode(byte[] plaintext) {
    ByteBuffer in = ByteBuffer.wrap(plaintext);
    int flags = in.get() & 0xFF;
    Payload p = new Payload();
    p.maxUses = in.get() & 0xFF;
    if (p.maxUses > MAX_USES_LIMIT) {
      throw new IllegalArgumentException("maxUses out of range");
    }
    p.expiry = Integer.toUnsignedLong(in.getInt());
    p.issuedAt = Integer.toUnsignedLong(in.getInt());
    if ((flags & FLAG_HAS_LOA) != 0) {
      p.loa = (int) in.get();
    }
    if ((flags & FLAG_USER_ID_IS_UUID) != 0) {
      p.userId = new UUID(in.getLong(), in.getLong()).toString();
    } else {
      p.userId = readString(in);
    }
    if ((flags & FLAG_HAS_CLIENT) != 0) {
      p.clientId = readString(in);
    }
    if (in.hasRemaining()) {
      throw new IllegalArgumentException("trailing bytes");
    }
    p.rememberMe = (flags & FLAG_REMEMBER_ME) != 0;
    p.setEmailVerified = (flags & FLAG_SET_EMAIL_VERIFIED) != 0;
    p.confirmUserSwitch = (flags & FLAG_CONFIRM_USER_SWITCH) != 0;
    return p;
  }

  /** Returns the UUID only if {@code value} is its canonical lower-case text form. */
  private static UUID canonicalUuid(String value) {
    if (value.length() != 36) {
      return null;
    }
    try {
      UUID uuid = UUID.fromString(value);
      return uuid.toString().equals(value) ? uuid : null;
    } catch (IllegalArgumentException e) {
      return null;
    }
  }

  private static void writeString(ByteArrayOutputStream out, String value) {
    byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
    if (bytes.length > 255) {
      throw new IllegalArgumentException("value too long for a stateless login token");
    }
    out.write(bytes.length);
    out.writeBytes(bytes);
  }

  private static String readString(ByteBuffer in) {
    byte[] bytes = new byte[in.get() & 0xFF];
    in.get(bytes);
    return new String(bytes, StandardCharsets.UTF_8);
  }

  private static byte[] slice(byte[] source, int from, int length) {
    byte[] result = new byte[length];
    System.arraycopy(source, from, result, 0, length);
    return result;
  }
}
