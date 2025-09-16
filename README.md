# 🔐 Spring Boot Authentication & Authorization Server

[![MIT License](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Spring Boot](https://img.shields.io/badge/Spring%20Boot-3.x-brightgreen.svg)](https://spring.io/projects/spring-boot)
[![Java](https://img.shields.io/badge/Java-17+-blue.svg)](https://openjdk.org/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-15+-336791.svg)](https://www.postgresql.org/)
[![Redis](https://img.shields.io/badge/Redis-7+-DC382D.svg)](https://redis.io/)

A secure, scalable, and feature-rich authentication and authorization server built with Spring Boot. Supports manual and OAuth2 (Google) login, JWT-based sessions, Redis integration, and enterprise-grade security measures.

---

## ✨ Features

- **🔐 Multi-Factor Authentication** - Manual signup/login + Google OAuth2 integration
- **📧 Email Verification & Password Reset** - Secure token-based flows with expiration
- **🔄 JWT & Refresh Token Management** - Redis-backed token blacklisting and refresh
- **🛡️ Advanced Security** - reCAPTCHA v3, hybrid rate limiting, bcrypt password hashing
- **🔗 Account Linking** - Merge manual and Google accounts seamlessly
- **👥 Role-Based Access Control** - Fine-grained permissions (ROLE_USER, ROLE_ADMIN)
- **⚡ Redis Integration** - Caching, rate limiting, token storage, and blacklisting
- **🐳 Docker Ready** - Containerized deployment support
- **📈 Production Ready** - Designed for cloud deployment and scaling

---

## 🏗️ System Architecture

### Technology Stack
- **Backend**: Spring Boot 3.x (Web, Security, Data JPA, OAuth2)
- **Database**: PostgreSQL with optimized user schema
- **Cache/Storage**: Redis for performance and security
- **Authentication**: JWT, Google OAuth2, reCAPTCHA v3
- **Security**: HTTPS, bcrypt, hybrid rate limiting, token blacklisting
- **Build**: Maven, Lombok, Spring Initializr

### Database Schema
```sql
users (
    id UUID PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    google_id VARCHAR(255) UNIQUE NULL,
    role VARCHAR(50) NOT NULL,
    created TIMESTAMP NOT NULL
)