package murraco.controller;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import murraco.model.AppUser;
import murraco.repository.UserRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;

@SpringBootTest
@AutoConfigureMockMvc
class UserControllerTest {

  private static final String ADMIN_USER = "admin";
  private static final String ADMIN_PASSWORD = "admin123456";
  private static final String LOCKOUT_PASSWORD = "password12";
  private static final String WRONG_PASSWORD = "wrong-password";
  private static final int MAX_FAILED_ATTEMPTS = 5;
  private static final Duration LOCKOUT_DURATION = Duration.ofMinutes(15);

  @Autowired
  private MockMvc mockMvc;

  @Autowired
  private ObjectMapper objectMapper;

  @Autowired
  private UserRepository userRepository;

  /** Signs in and returns the token pair as {accessToken, refreshToken, ...}. */
  private JsonNode signin() throws Exception {
    String body = mockMvc.perform(post("/users/signin")
            .param("username", ADMIN_USER)
            .param("password", ADMIN_PASSWORD))
        .andExpect(status().isOk())
        .andReturn()
        .getResponse()
        .getContentAsString();
    return objectMapper.readTree(body);
  }

  /** Signs up a fresh user so lockout tests never lock the shared admin account. */
  private String createLockoutUser() throws Exception {
    String username = "lockout-" + UUID.randomUUID().toString().substring(0, 8);
    String body = """
        {"username":"%s","email":"%s@example.com","password":"%s","appUserRoles":["ROLE_CLIENT"]}
        """.formatted(username, username, LOCKOUT_PASSWORD);
    mockMvc.perform(post("/users/signup")
            .contentType(MediaType.APPLICATION_JSON)
            .content(body))
        .andExpect(status().isOk());
    return username;
  }

  private ResultActions signin(String username, String password) throws Exception {
    return mockMvc.perform(post("/users/signin")
        .param("username", username)
        .param("password", password));
  }

  private void failSignin(String username, int times) throws Exception {
    for (int i = 0; i < times; i++) {
      signin(username, WRONG_PASSWORD).andExpect(status().isUnprocessableEntity());
    }
  }

  /** The service reads the wall clock, so moving the lock into the past stands in for waiting it out. */
  private void moveLockedUntil(String username, Instant lockedUntil) {
    AppUser user = userRepository.findByUsername(username);
    user.setLockedUntil(lockedUntil);
    userRepository.save(user);
  }

  private String refreshBody(String refreshToken) throws Exception {
    return objectMapper.writeValueAsString(java.util.Map.of("refreshToken", refreshToken));
  }

  @Test
  void signin_withValidCredentials_returnsTokenPair() throws Exception {
    JsonNode tokens = signin();
    assertTrue(tokens.get("accessToken").asText().length() > 20, "Expected a JWT access token");
    assertTrue(tokens.get("refreshToken").asText().length() > 20, "Expected a refresh token");
    assertTrue(tokens.get("expiresIn").asLong() > 0, "Expected a positive access token lifetime");
  }

  @Test
  void me_withoutToken_returns403() throws Exception {
    mockMvc.perform(get("/users/me"))
        .andExpect(status().isForbidden());
  }

  @Test
  void me_withValidToken_returnsUserData() throws Exception {
    String accessToken = signin().get("accessToken").asText();

    mockMvc.perform(get("/users/me")
            .header("Authorization", "Bearer " + accessToken))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.username").value(ADMIN_USER))
        .andExpect(jsonPath("$.email").value("admin@email.com"))
        .andExpect(jsonPath("$.appUserRoles").isArray());
  }

  @Test
  void refresh_withValidRefreshToken_returnsNewPair() throws Exception {
    JsonNode tokens = signin();
    String refreshToken = tokens.get("refreshToken").asText();

    String body = mockMvc.perform(post("/users/refresh")
            .contentType(MediaType.APPLICATION_JSON)
            .content(refreshBody(refreshToken)))
        .andExpect(status().isOk())
        .andReturn()
        .getResponse()
        .getContentAsString();

    JsonNode refreshed = objectMapper.readTree(body);
    assertTrue(refreshed.get("accessToken").asText().length() > 20, "Expected a new access token");
    assertNotEquals(refreshToken, refreshed.get("refreshToken").asText(), "Refresh token should rotate");

    // The new access token must actually work.
    mockMvc.perform(get("/users/me")
            .header("Authorization", "Bearer " + refreshed.get("accessToken").asText()))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.username").value(ADMIN_USER));
  }

  @Test
  void refresh_worksWithoutAccessToken() throws Exception {
    // The whole point of a refresh token: it works when the access token is expired or bogus.
    String refreshToken = signin().get("refreshToken").asText();

    mockMvc.perform(post("/users/refresh")
            .header("Authorization", "Bearer expired-and-invalid")
            .contentType(MediaType.APPLICATION_JSON)
            .content(refreshBody(refreshToken)))
        .andExpect(status().isOk());
  }

  @Test
  void refresh_reusingRotatedToken_returns401() throws Exception {
    String refreshToken = signin().get("refreshToken").asText();

    mockMvc.perform(post("/users/refresh")
            .contentType(MediaType.APPLICATION_JSON)
            .content(refreshBody(refreshToken)))
        .andExpect(status().isOk());

    // Second use of the same token is a reuse attempt and must be rejected.
    mockMvc.perform(post("/users/refresh")
            .contentType(MediaType.APPLICATION_JSON)
            .content(refreshBody(refreshToken)))
        .andExpect(status().isUnauthorized());
  }

  @Test
  void refresh_afterReuseDetection_revokesRemainingTokens() throws Exception {
    String refreshToken = signin().get("refreshToken").asText();

    String body = mockMvc.perform(post("/users/refresh")
            .contentType(MediaType.APPLICATION_JSON)
            .content(refreshBody(refreshToken)))
        .andExpect(status().isOk())
        .andReturn()
        .getResponse()
        .getContentAsString();
    String rotated = objectMapper.readTree(body).get("refreshToken").asText();

    // Replaying the consumed token signals theft, which invalidates the whole family.
    mockMvc.perform(post("/users/refresh")
            .contentType(MediaType.APPLICATION_JSON)
            .content(refreshBody(refreshToken)))
        .andExpect(status().isUnauthorized());

    mockMvc.perform(post("/users/refresh")
            .contentType(MediaType.APPLICATION_JSON)
            .content(refreshBody(rotated)))
        .andExpect(status().isUnauthorized());
  }

  @Test
  void refresh_withUnknownToken_returns401() throws Exception {
    mockMvc.perform(post("/users/refresh")
            .contentType(MediaType.APPLICATION_JSON)
            .content(refreshBody("not-a-real-refresh-token")))
        .andExpect(status().isUnauthorized());
  }

  @Test
  void refresh_withBlankToken_returns400() throws Exception {
    mockMvc.perform(post("/users/refresh")
            .contentType(MediaType.APPLICATION_JSON)
            .content(refreshBody("")))
        .andExpect(status().isBadRequest());
  }

  @Test
  void logout_revokesRefreshToken() throws Exception {
    String refreshToken = signin().get("refreshToken").asText();

    mockMvc.perform(post("/users/logout")
            .contentType(MediaType.APPLICATION_JSON)
            .content(refreshBody(refreshToken)))
        .andExpect(status().isNoContent());

    mockMvc.perform(post("/users/refresh")
            .contentType(MediaType.APPLICATION_JSON)
            .content(refreshBody(refreshToken)))
        .andExpect(status().isUnauthorized());
  }

  @Test
  void logout_withUnknownToken_isIdempotent() throws Exception {
    mockMvc.perform(post("/users/logout")
            .contentType(MediaType.APPLICATION_JSON)
            .content(refreshBody("never-issued")))
        .andExpect(status().isNoContent());
  }

  @Test
  void signup_returnsTokenPair() throws Exception {
    String body = """
        {"username":"newuser","email":"newuser@example.com","password":"password12","appUserRoles":["ROLE_CLIENT"]}
        """;
    String response = mockMvc.perform(post("/users/signup")
            .contentType(MediaType.APPLICATION_JSON)
            .content(body))
        .andExpect(status().isOk())
        .andReturn()
        .getResponse()
        .getContentAsString();

    JsonNode tokens = objectMapper.readTree(response);
    assertTrue(tokens.get("accessToken").asText().length() > 20, "Expected a JWT access token");
    assertTrue(tokens.get("refreshToken").asText().length() > 20, "Expected a refresh token");
  }

  @Test
  void signup_duplicateUsername_returns422() throws Exception {
    String body = """
        {"username":"admin","email":"other@example.com","password":"password12","appUserRoles":["ROLE_CLIENT"]}
        """;
    mockMvc.perform(post("/users/signup")
            .contentType(MediaType.APPLICATION_JSON)
            .content(body))
        .andExpect(status().isUnprocessableEntity());
  }

  @Test
  void me_withMalformedToken_returns401() throws Exception {
    mockMvc.perform(get("/users/me")
            .header("Authorization", "Bearer not-a-valid-jwt"))
        .andExpect(status().isUnauthorized());
  }

  @Test
  void signin_afterFourFailedAttempts_isNotLocked() throws Exception {
    String username = createLockoutUser();
    failSignin(username, MAX_FAILED_ATTEMPTS - 1);

    signin(username, LOCKOUT_PASSWORD).andExpect(status().isOk());
  }

  @Test
  void signin_afterFiveFailedAttempts_returns423EvenWithCorrectPassword() throws Exception {
    String username = createLockoutUser();
    failSignin(username, MAX_FAILED_ATTEMPTS);

    signin(username, LOCKOUT_PASSWORD).andExpect(status().isLocked());
    // While locked, wrong guesses are rejected the same way, so the lock doesn't leak whether a password is right.
    signin(username, WRONG_PASSWORD).andExpect(status().isLocked());
  }

  @Test
  void signin_afterFiveFailedAttempts_locksForFifteenMinutes() throws Exception {
    String username = createLockoutUser();
    Instant before = Instant.now();
    failSignin(username, MAX_FAILED_ATTEMPTS);
    Instant after = Instant.now();

    Instant lockedUntil = userRepository.findByUsername(username).getLockedUntil();
    assertNotNull(lockedUntil, "Expected the account to be locked");
    assertTrue(!lockedUntil.isBefore(before.plus(LOCKOUT_DURATION)) && !lockedUntil.isAfter(after.plus(LOCKOUT_DURATION)),
        "Expected the lock to last 15 minutes, but it ends at " + lockedUntil);
  }

  @Test
  void signin_shortlyBeforeLockExpires_isStillLocked() throws Exception {
    String username = createLockoutUser();
    failSignin(username, MAX_FAILED_ATTEMPTS);

    // 14 minutes into the 15-minute lock.
    moveLockedUntil(username, Instant.now().plus(Duration.ofMinutes(1)));

    signin(username, LOCKOUT_PASSWORD).andExpect(status().isLocked());
  }

  @Test
  void signin_afterLockExpires_isAllowedAgain() throws Exception {
    String username = createLockoutUser();
    failSignin(username, MAX_FAILED_ATTEMPTS);
    signin(username, LOCKOUT_PASSWORD).andExpect(status().isLocked());

    // 15 minutes have passed.
    moveLockedUntil(username, Instant.now().minusSeconds(1));

    signin(username, LOCKOUT_PASSWORD)
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.accessToken").isNotEmpty());
    AppUser user = userRepository.findByUsername(username);
    assertNull(user.getLockedUntil(), "A successful sign-in should clear the expired lock");
    assertEquals(0, user.getFailedLoginAttempts());
  }

  @Test
  void signin_afterLockExpires_getsFiveFreshAttempts() throws Exception {
    String username = createLockoutUser();
    failSignin(username, MAX_FAILED_ATTEMPTS);
    moveLockedUntil(username, Instant.now().minusSeconds(1));

    failSignin(username, MAX_FAILED_ATTEMPTS - 1);
    signin(username, LOCKOUT_PASSWORD).andExpect(status().isOk());
  }

  @Test
  void signin_success_resetsFailedAttemptCount() throws Exception {
    String username = createLockoutUser();
    failSignin(username, MAX_FAILED_ATTEMPTS - 1);
    assertEquals(MAX_FAILED_ATTEMPTS - 1, userRepository.findByUsername(username).getFailedLoginAttempts());

    signin(username, LOCKOUT_PASSWORD).andExpect(status().isOk());
    assertEquals(0, userRepository.findByUsername(username).getFailedLoginAttempts());

    // Without the reset, the next failure would be the fifth in a row and lock the account.
    failSignin(username, MAX_FAILED_ATTEMPTS - 1);
    signin(username, LOCKOUT_PASSWORD).andExpect(status().isOk());
  }

  @Test
  void signin_failedAttemptsOnOneUser_doNotLockAnother() throws Exception {
    String locked = createLockoutUser();
    String other = createLockoutUser();
    failSignin(locked, MAX_FAILED_ATTEMPTS);

    signin(locked, LOCKOUT_PASSWORD).andExpect(status().isLocked());
    signin(other, LOCKOUT_PASSWORD).andExpect(status().isOk());
  }

  @Test
  void signin_parallelWrongPasswords_getOnlyFivePasswordChecks() throws Exception {
    String username = createLockoutUser();
    int requests = 20;
    ExecutorService pool = Executors.newFixedThreadPool(requests);
    CountDownLatch start = new CountDownLatch(1);
    List<Future<Integer>> statuses = new ArrayList<>();
    for (int i = 0; i < requests; i++) {
      statuses.add(pool.submit(() -> {
        start.await();
        return signin(username, WRONG_PASSWORD).andReturn().getResponse().getStatus();
      }));
    }
    start.countDown();

    int passwordChecks = 0;
    int locked = 0;
    for (Future<Integer> status : statuses) {
      int code = status.get(1, TimeUnit.MINUTES);
      if (code == 422) {
        passwordChecks++;
      } else if (code == 423) {
        locked++;
      }
    }
    pool.shutdown();

    // A burst must not get more guesses than sequential requests would.
    assertEquals(MAX_FAILED_ATTEMPTS, passwordChecks, "Password checks in a parallel burst");
    assertEquals(requests - MAX_FAILED_ATTEMPTS, locked, "Requests rejected as locked");
    signin(username, LOCKOUT_PASSWORD).andExpect(status().isLocked());
  }
}
