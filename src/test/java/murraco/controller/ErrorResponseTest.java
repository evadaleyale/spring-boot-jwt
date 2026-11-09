package murraco.controller;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;

/**
 * Runs against a real server because MockMvc doesn't forward {@code sendError} to {@code /error},
 * so it can't catch error statuses being replaced on the way to the client.
 */
@SpringBootTest(
    webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
    properties = "spring.datasource.url=jdbc:h2:mem:error_response_test;DB_CLOSE_DELAY=-1")
class ErrorResponseTest {

  private static final String PASSWORD = "password12";

  @Autowired
  private TestRestTemplate restTemplate;

  private String createUser() {
    String username = "http-" + UUID.randomUUID().toString().substring(0, 8);
    String body = """
        {"username":"%s","email":"%s@example.com","password":"%s","appUserRoles":["ROLE_CLIENT"]}
        """.formatted(username, username, PASSWORD);
    HttpHeaders headers = new HttpHeaders();
    headers.setContentType(MediaType.APPLICATION_JSON);
    ResponseEntity<String> response = restTemplate.postForEntity("/users/signup", new HttpEntity<>(body, headers), String.class);
    assertEquals(HttpStatus.OK, response.getStatusCode());
    return username;
  }

  private ResponseEntity<String> signin(String username, String password) {
    return restTemplate.postForEntity("/users/signin?username={username}&password={password}", null, String.class,
        username, password);
  }

  @Test
  void signin_wrongPassword_returns422ToClient() {
    ResponseEntity<String> response = signin(createUser(), "wrong-password");

    assertEquals(HttpStatus.UNPROCESSABLE_ENTITY, response.getStatusCode());
    assertTrue(response.getBody().contains("\"status\":422"), "Expected an error body, got: " + response.getBody());
  }

  @Test
  void signin_lockedAccount_returns423ToClient() {
    String username = createUser();
    for (int i = 0; i < 5; i++) {
      assertEquals(HttpStatus.UNPROCESSABLE_ENTITY, signin(username, "wrong-password").getStatusCode());
    }

    ResponseEntity<String> response = signin(username, PASSWORD);

    assertEquals(HttpStatus.LOCKED, response.getStatusCode());
    assertTrue(response.getBody().contains("\"status\":423"), "Expected an error body, got: " + response.getBody());
  }

  @Test
  void me_withoutToken_isStillForbidden() {
    // Permitting /error must not open up protected endpoints.
    assertEquals(HttpStatus.FORBIDDEN, restTemplate.getForEntity("/users/me", String.class).getStatusCode());
  }
}
