package murraco.repository;

import jakarta.transaction.Transactional;

import java.time.Instant;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;

import murraco.model.AppUser;

public interface UserRepository extends JpaRepository<AppUser, Integer> {

  boolean existsByUsername(String username);

  AppUser findByUsername(String username);

  @Transactional
  void deleteByUsername(String username);

  @Transactional
  @Modifying
  @Query("update AppUser u set u.failedLoginAttempts = u.failedLoginAttempts + 1 where u.username = :username")
  void incrementFailedLoginAttempts(String username);

  @Transactional
  @Modifying
  @Query("update AppUser u set u.failedLoginAttempts = 0, u.lockedUntil = :lockedUntil"
      + " where u.username = :username and u.failedLoginAttempts >= :maxAttempts")
  int lockIfAttemptsReached(String username, int maxAttempts, Instant lockedUntil);

}
