package murraco.service;

import java.time.Duration;
import java.time.Instant;

import jakarta.servlet.http.HttpServletRequest;

import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import murraco.dto.AuthResponseDTO;
import murraco.exception.CustomException;
import murraco.model.AppUser;
import murraco.repository.UserRepository;
import murraco.security.JwtTokenProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Service
@RequiredArgsConstructor
public class UserService {

  private static final Logger log = LoggerFactory.getLogger(UserService.class);

  private static final String TOKEN_TYPE = "Bearer";

  private static final int MAX_FAILED_LOGIN_ATTEMPTS = 5;
  private static final Duration LOCKOUT_DURATION = Duration.ofMinutes(15);

  private final UserRepository userRepository;
  private final PasswordEncoder passwordEncoder;
  private final JwtTokenProvider jwtTokenProvider;
  private final AuthenticationManager authenticationManager;
  private final RefreshTokenService refreshTokenService;

  public AuthResponseDTO signin(String username, String password) {
    AppUser appUser = userRepository.findByUsername(username);
    if (appUser != null && appUser.getLockedUntil() != null && appUser.getLockedUntil().isAfter(Instant.now())) {
      throw new CustomException("Account is temporarily locked due to too many failed sign-in attempts", HttpStatus.LOCKED);
    }
    try {
      authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
    } catch (AuthenticationException e) {
      if (appUser != null) {
        recordFailedSignin(appUser);
      }
      throw new CustomException("Invalid username/password supplied", HttpStatus.UNPROCESSABLE_ENTITY);
    }
    if (appUser.getFailedLoginAttempts() > 0 || appUser.getLockedUntil() != null) {
      appUser.setFailedLoginAttempts(0);
      appUser.setLockedUntil(null);
      userRepository.save(appUser);
    }
    log.info("User signed in: {}", username);
    return issueTokens(appUser);
  }

  private void recordFailedSignin(AppUser appUser) {
    userRepository.incrementFailedLoginAttempts(appUser.getUsername());
    if (userRepository.lockIfAttemptsReached(appUser.getUsername(), MAX_FAILED_LOGIN_ATTEMPTS,
        Instant.now().plus(LOCKOUT_DURATION)) > 0) {
      log.warn("User locked out after {} failed sign-in attempts: {}", MAX_FAILED_LOGIN_ATTEMPTS, appUser.getUsername());
    }
  }

  public AuthResponseDTO signup(AppUser appUser) {
    AppUser created = register(appUser);
    return issueTokens(created);
  }

  /** Persists a new user without issuing tokens, e.g. when seeding demo accounts on startup. */
  public AppUser register(AppUser appUser) {
    if (userRepository.existsByUsername(appUser.getUsername())) {
      throw new CustomException("Username is already in use", HttpStatus.UNPROCESSABLE_ENTITY);
    }
    appUser.setPassword(passwordEncoder.encode(appUser.getPassword()));
    userRepository.save(appUser);
    log.info("User signed up: {}", appUser.getUsername());
    return appUser;
  }

  public void delete(String username) {
    refreshTokenService.deleteAllForUser(username);
    userRepository.deleteByUsername(username);
  }

  public AppUser search(String username) {
    AppUser appUser = userRepository.findByUsername(username);
    if (appUser == null) {
      throw new CustomException("The user doesn't exist", HttpStatus.NOT_FOUND);
    }
    return appUser;
  }

  public AppUser whoami(HttpServletRequest req) {
    String token = jwtTokenProvider.resolveToken(req);
    if (token == null) {
      throw new CustomException("Missing or invalid Authorization header", HttpStatus.UNAUTHORIZED);
    }
    AppUser appUser = userRepository.findByUsername(jwtTokenProvider.getUsername(token));
    if (appUser == null) {
      throw new CustomException("The user doesn't exist", HttpStatus.NOT_FOUND);
    }
    return appUser;
  }

  /**
   * Exchanges a refresh token for a fresh token pair. The presented refresh token is consumed:
   * a new one is returned and must replace it on the client.
   */
  public AuthResponseDTO refresh(String refreshToken) {
    RefreshTokenService.Rotation rotation = refreshTokenService.rotate(refreshToken);

    AppUser appUser = userRepository.findByUsername(rotation.username());
    if (appUser == null) {
      throw new CustomException("The user doesn't exist", HttpStatus.NOT_FOUND);
    }

    String accessToken = jwtTokenProvider.createToken(appUser.getUsername(), appUser.getAppUserRoles());
    log.info("Refreshed tokens for user: {}", appUser.getUsername());
    return new AuthResponseDTO(accessToken, rotation.newRefreshToken(), TOKEN_TYPE, jwtTokenProvider.getValidityInSeconds());
  }

  /** Revokes a refresh token so it can no longer be exchanged. */
  public void logout(String refreshToken) {
    refreshTokenService.revoke(refreshToken);
  }

  private AuthResponseDTO issueTokens(AppUser appUser) {
    String accessToken = jwtTokenProvider.createToken(appUser.getUsername(), appUser.getAppUserRoles());
    String refreshToken = refreshTokenService.issue(appUser.getUsername());
    return new AuthResponseDTO(accessToken, refreshToken, TOKEN_TYPE, jwtTokenProvider.getValidityInSeconds());
  }

}
