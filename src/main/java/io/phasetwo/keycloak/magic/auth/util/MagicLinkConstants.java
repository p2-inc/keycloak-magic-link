package io.phasetwo.keycloak.magic.auth.util;

public final class MagicLinkConstants {
  public static final String SESSION_INITIATED = "SESSION_INITIATED";
  public static final String SESSION_EXPIRATION = "SESSION_EXPIRATION";
  public static final String SESSION_CONFIRMED = "SESSION_CONFIRMED";

  public static final String TIMEOUT = "TIMEOUT";
  public static final String AUTH_SESSION_ID = "AUTH_SESSION_ID";

  // Magic Link Continuation state management
  public static final String MLC_STATE = "MLC_STATE";
  public static final String STATE_PENDING = "pending";
  public static final String STATE_CONFIRMED = "confirmed";
  public static final String STATE_EXPIRED = "expired";
  public static final String AUTH_SESSION_EXP = "auth_session_exp";
}
