# User Authentication and Authorization Server Documentation

## Version
1.0

## Introduction
This document outlines the design and functionality of the User Authentication and Authorization Server , a backend Spring Boot application for secure user authentication and authorization via REST APIs. The system supports manual signup/login (with email verification), Google OAuth2 signup/login (with username and password prompt), account linking, password reset, logout, and JWT refresh to maintain sessions until explicit logout. All users have a unique email, username, and non-nullable password. It integrates Redis for temporary storage, caching, rate limiting, token blacklisting, and refresh token management; Google reCAPTCHA v3 for bot protection; and hybrid rate limiting (email/IP-based) to prevent abuse. JSON Web Tokens (JWTs) are short-lived, paired with long-lived refresh tokens for session continuity, designed for testing with tools like Postman.

## System Architecture
### Technology Stack
- Framework: Spring Boot (Web, Security, Data JPA)
- Database: Relational (PostgreSQL) with users table
- Caching/Storage/Rate Limiting/Blacklisting: Redis
- External Services:
  - Google OAuth2 (scopes: openid, email, profile)
  - Google reCAPTCHA v3 for bot protection
  - Email service (google email) for verification/reset links
- Security: Bcrypt password hashing, JWT, refresh tokens, HTTPS, secure Redis (authentication, TLS)
- Other: Maven, Lombok, Spring Initializr

### Database Schema
- Table: users
- Columns:
  - id: UUID, primary key, auto-incremented
  - username: VARCHAR, unique, not null
  - email: VARCHAR, unique, not null
  - password: VARCHAR, not null (bcrypt-hashed)
  - google_id: VARCHAR, nullable, unique when set (Google’s sub)
  - role: VARCHAR, not null (e.g., ROLE_USER, ROLE_ADMIN)
  - created: date time
- Constraints: Unique indexes on username, email, google_id (when non-null)

### Redis Usage
- Temporary Storage (TTL for expiration/auto-deletion):
  - Manual signup: signup:manual:<verification_token> (TTL: 24 hours, {email, username, password:hash, created_at})
  - Google signup: signup:<signup_token> (TTL: 10 minutes, {email, google_id, name})
  - Account linking: link:<link_token> (TTL: 10 minutes, {email, google_id})
  - Password reset: reset:<reset_token> (TTL: 24 hours, {email, created_at})
- Caching: User profiles (user:<email>, TTL: 1 hour, {username, email, role})
- Rate Limiting: ratelimit:<endpoint>:<email> or ratelimit:<endpoint>:<ip> (TTL: 1 hour, request count)
- Token Management: 
  - blacklist:<jwt> (TTL: JWT expiration, flag)
  - refresh:<refresh_token> (TTL: 7 days, {user_email, expiry})

### Security Features
- JWT: Short-lived (e.g., 15 minutes), issued post-signup/login/linking/reset; includes username, role; validated via filter with Redis blacklist check
- Refresh Token: Long-lived (e.g., 7 days), issued with JWT, stored in Redis, used to refresh JWT via /api/auth/refresh until logout
- Passwords: Bcrypt-hashed, non-nullable, enforced strength (e.g., 8+ characters, mixed case)
- Google OAuth2: ID token verification
- reCAPTCHA v3: Protects unauthenticated endpoints; score threshold (e.g., >0.5 for human)
- Hybrid Rate Limiting:
  - Email-based: 3–5 requests/hour (e.g., reset/signup)
  - IP-based fallback: 10 requests/hour for unauthenticated endpoints
- Logout: Blacklists JWT and invalidates refresh token in Redis to end session
- Other: HTTPS, secure tokens (UUID/cryptographically secure), logging

## Features
1. Manual Signup: Email, username, password; requires email verification; issues JWT + refresh token
2. Google OAuth2 Signup: Google authentication, username/password prompt; issues JWT + refresh token
3. Manual Login: Email/username and password; issues JWT + refresh token
4. Google OAuth2 Login: Password-free if google_id matches; issues JWT + refresh token
5. Account Linking: Manual users link Google accounts with password; issues JWT + refresh token
6. Password Reset: Email-based link, 24-hour expiration; issues JWT + refresh token
7. JWT Refresh: Refreshes JWT using refresh token, maintains login until logout
8. Logout: Invalidates JWT and refresh token, ends session
9. Role-Based Access: Restrict endpoints (e.g., /api/admin for ROLE_ADMIN)
10. Bot/Abuse Protection: reCAPTCHA v3, hybrid rate limiting

## API Endpoints
### Unprotected (Unauthenticated)
- POST /api/auth/register: {email, username, password, recaptchaToken}; starts manual signup
- POST /api/auth/resend-verification: {email, recaptchaToken}; resends verification link
- GET /api/auth/verify-email?token=<verification_token>: Verifies signup, issues JWT + refresh token
- GET /api/auth/google: Initiates Google OAuth2
- GET /api/auth/google/callback: Handles Google callback
- POST /api/auth/complete-signup: {signup_token, username, password, recaptchaToken}; completes Google signup, issues JWT + refresh token
- POST /api/auth/request-password-reset: {email, recaptchaToken}; starts password reset
- GET /api/auth/reset-password?token=<reset_token>: Initiates reset (optional form)
- POST /api/auth/complete-reset-password: {reset_token, password}; completes reset, issues JWT + refresh token
- POST /api/auth/login: {email/username, password}; manual login, issues JWT + refresh token

### Protected (Require JWT)
- POST /api/auth/link-google: {link_token, password}; links Google account, issues JWT + refresh token
- POST /api/auth/refresh: {refresh_token}; refreshes JWT
- POST /api/auth/logout: Authorization: Bearer <jwt>; blacklists JWT, invalidates refresh token
- /api/admin: Example endpoint, requires ROLE_ADMIN

## Detailed Flows
### Manual Signup
1. POST /api/auth/register with reCAPTCHA token
2. Validate reCAPTCHA, rate limits (email: 3/hour, IP: 10/hour)
3. Store in Redis (signup:manual:<verification_token>, TTL: 24 hours)
4. Send verification email
5. GET /api/auth/verify-email, create user, issue JWT + refresh token
6. Resend via /api/auth/resend-verification if expired

### Google OAuth2 Signup
1. GET /api/auth/google, redirect to Google
2. GET /api/auth/google/callback, store in Redis (signup:<signup_token>, TTL: 10 minutes)
3. POST /api/auth/complete-signup with reCAPTCHA token, username, password
4. Validate reCAPTCHA, rate limits (email: 5/hour, IP: 10/hour)
5. Create user, issue JWT + refresh token

### Manual Login
1. POST /api/auth/login with email/username, password, optional reCAPTCHA
2. Validate reCAPTCHA (if used), rate limit (email: 10/hour, optional)
3. Verify password, cache user in Redis, issue JWT + refresh token

### Google OAuth2 Login
1. Authenticate via Google, match google_id or email
2. If google_id matches, issue JWT + refresh token
3. If email matches, null google_id, initiate linking

### Account Linking
1. Manual user attempts Google login
2. Store in Redis (link:<link_token>, TTL: 10 minutes)
3. POST /api/auth/link-google with reCAPTCHA token, password
4. Validate reCAPTCHA, rate limit (email: 5/hour)
5. Verify password, set google_id, issue JWT + refresh token

### Password Reset
1. POST /api/auth/request-password-reset with reCAPTCHA token
2. Validate reCAPTCHA, rate limits (email: 3/hour for existing, IP: 10/hour)
3. Store in Redis (reset:<reset_token>, TTL: 24 hours)
4. Send reset email
5. POST /api/auth/complete-reset-password, update password, issue JWT + refresh token
6. Resend via /api/auth/request-password-reset if expired

### JWT Refresh
1. POST /api/auth/refresh with refresh_token
2. Validate refresh token in Redis
3. Issue new JWT, extend session

### Logout
1. POST /api/auth/logout with Authorization: Bearer <jwt>
2. Validate JWT, blacklist JWT, invalidate refresh token in Redis
3. Return “Logged out successfully”
4. JWT filter rejects blacklisted tokens

## Edge Cases and Handling
1. Duplicate Email/Username: Return “Email/username already taken.”
2. Expired Tokens: Resend via respective endpoints.
3. Invalid Tokens: Return “Invalid token.”
4. Weak Password: Return “Password too weak.”
5. Email Failure: Log, return “Try again.”
6. Rate Limit Exceeded: Return HTTP 429.
7. reCAPTCHA Failure: Return “Verify you’re not a robot.”
8. Fake Emails: reCAPTCHA, IP-based rate limiting.
9. Multiple Requests: Delete old Redis entries.
10. Invalid Refresh Token: Return “Invalid refresh token.”
11. Expired Refresh Token: Return “Session expired, re-login.”
12. Logout with Invalid JWT: Return HTTP 401.

## Deployment and Monitoring
- Deployment: Docker, cloud (AWS).
- Monitoring: Spring Boot Actuator, logs for security events.
- Scalability: Redis for distributed caching/rate limiting/blacklisting.

## Future Enhancements
- Support multi-factor authentication (MFA).
- Integrate additional OAuth providers (e.g., Facebook).

## Contact
For updates or issues, contact the development team or refer to project sources.
