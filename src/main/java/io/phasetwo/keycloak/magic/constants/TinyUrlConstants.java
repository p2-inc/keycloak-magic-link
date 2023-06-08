package io.phasetwo.keycloak.magic.constants;

public interface TinyUrlConstants {
  String ACTION_TOKEN_URL_PATH = "login-actions/action-token";

  int NUMBER_OF_RETRIES_FOR_UNIQUE_URL_KEY = 10;

  long TINY_URL_CLEANUP_INTERVAL = 3600000;
}
