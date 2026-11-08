# Threat model: evadaleyale/spring-boot-jwt

_Facts marked **(user)** come from the repository owner's answers; everything else is read from the code._

## System overview
A stateless Spring Boot 3.5 (Java 17) REST service handling user signup, signin and JWT authentication. It ships as one jar (`Dockerfile`, port 8080). There is no frontend and no infrastructure-as-code: no infrastructure repository exists **(user)**, so the network layout (TLS termination, gateway, WAF) is unknown.

- **Deployment:** treated as an **internet-facing production service** **(user)**. The user did not write this public repository, so nothing is assumed to be dev-only.
- **Database:** H2 in memory by default (`application.yml` activates the `dev` profile); MySQL driver available.

## Components
| Component | Code | Notes |
|---|---|---|
| **API** | `src/main/java/murraco/controller/`, `dto/`, `exception/`, `configuration/OpenApiConfig.java` | `/users/*` endpoints, request DTO validation, error handling, Swagger/OpenAPI |
| **Auth** | `src/main/java/murraco/security/`, `service/UserService.java`, `service/RefreshTokenService.java` | JWT issuing and validation, filter chain, role checks, password hashing, refresh-token rotation |
| **Persistence** | `src/main/java/murraco/model/`, `repository/`, `src/main/resources/*.yml` | JPA entities `AppUser` and `RefreshToken`, Spring Data repositories, datasource and H2 console config |
| **Bootstrap** | `src/main/java/murraco/JwtAuthServiceApp.java` | Seeds `admin`/`admin123456` (ROLE_ADMIN) and `client`/`client123456` on startup |
| **Build & supply chain** | `pom.xml`, `mvnw*`, `.mvn/`, `Dockerfile`, `.github/` | Maven dependencies, container image, CI, Dependabot |

## Trust boundaries and entry points
1. **Internet → API (unauthenticated):** `POST /users/signin` (username and password as query/form params), `POST /users/signup` (`UserDataDTO`, which includes a client-supplied `appUserRoles`), `POST /users/refresh`, `POST /users/logout`; also `/h2-console/**`, `/v3/api-docs/**` and `/swagger-ui/**`, all `permitAll` in `WebSecurityConfig`.
2. **Authenticated CLIENT → API:** `GET /users/me`.
3. **ADMIN only:** `GET /users/{username}` and `DELETE /users/{username}` (`@PreAuthorize hasRole('ROLE_ADMIN')`).
4. **API → DB:** JPA via Spring Data; no native queries were seen.
5. **Build-time:** Maven Central dependencies, the Maven wrapper download, base images `maven:3.9-eclipse-temurin-17-alpine` and `eclipse-temurin:17-jre-alpine`, GitHub Actions.

## Assets (all weighted equally **(user)**)
- **Admin role integrity:** who can read or delete any user.
- **User credentials and PII:** BCrypt(12) password hashes, emails, usernames.
- **JWT signing secret and token integrity:** the HMAC key is SHA-256 of `security.jwt.token.secret-key` (env `JWT_SECRET`, default `secret-key`). Access tokens last 5 min by default (`JWT_EXPIRE_MS`) and carry roles in the `auth` claim, but authorities are reloaded from the DB on each request (`getAuthentication` → `MyUserDetails`).
- **Refresh tokens:** opaque 32-byte random values, stored as SHA-256 hashes, rotated on use. Reuse revokes all of the user's tokens. They last 7 days.
- **Availability** of the signin/signup/refresh endpoints.

## Attackers (all in scope **(user)**)
- **Unauthenticated internet users:** credential stuffing or brute force on signin (no rate limiting was seen), mass assignment on signup, exposed consoles and docs, default secrets and accounts.
- **Authenticated CLIENT users:** escalating to ADMIN, or reaching other users' data or accounts.
- **Holders of a stolen access or refresh token:** replay, refresh-rotation races, use after logout.
- **Malicious or vulnerable dependencies (supply chain):** Maven dependencies, wrapper, base images, CI actions.

## Existing controls
- Stateless sessions; CSRF disabled (bearer tokens only, no cookies).
- JJWT 0.12 `verifyWith(signingKey)` (HMAC, signed tokens only). Invalid tokens are rejected with 401 in `JwtTokenFilter`.
- The filter skips signin, signup, refresh and logout so a stale header does not block them.
- Method security on admin endpoints; custom 403 handler.
- BCrypt cost 12; `@Valid` on DTOs (password min length 8, email format).
- Refresh tokens are hashed at rest, rotated, and reuse triggers revocation (`@Transactional(dontRollbackOn = CustomException.class)`).
- Error attributes exclude exception class names; the generic handler returns "Something went wrong".
- Frame options are `sameOrigin` (needed for the H2 console).
- Dependabot for GitHub Actions.

## Out of scope / accepted risk
- **Nothing** **(user)**: every finding is in scope, including dev-profile defaults (H2 console, `root/root`, default JWT secret, seeded demo accounts) and access tokens that stay valid after logout until they expire.

## Open questions
- Is TLS terminated in front of the service, and is there any rate limiting or WAF upstream?
- Is the `dev` profile (H2 console enabled) actually what runs in production, or is a prod profile supplied at deploy time?
