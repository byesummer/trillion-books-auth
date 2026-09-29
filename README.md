# trillion-books-auth

**Trillion** — MSA 기반 온라인 서점의 인증/인가 서비스

> 8인 팀 MSA 프로젝트에서 인증/인가(auth-service, API Gateway의 인증·인가 필터, front-server 인증 연동)와 member 서비스를 담당했다. 이 저장소는 그중 auth-service이며, 팀 프로젝트 종료 후 보안·동시성 문제를 찾아 개선했다.

## 기능

- Access/Refresh 이중 토큰 발급·검증, **Refresh Token Rotation(RTR) + 재사용 탐지**
- 동시 토큰 재발급 레이스를 Redisson 분산 락(memberId 단위)으로 직렬화
- OAuth2(Google·PAYCO) 소셜 로그인 — 토큰을 URL로 노출하지 않는 **일회성 교환 코드** 방식
- 로그아웃 토큰 무효화 — Redis 블랙리스트(잔여 TTL만큼 등록)
- `ErrorCode`/`AuthException` 통합 예외 체계, `X-Auth-Error` 헤더로 만료·위조·블랙리스트 사유 구분

## 기술 스택

| 분류 | 스택 |
|---|---|
| Language | Java 21 |
| Framework | Spring Boot 3.5.7, Spring Security |
| Cloud | Spring Cloud 2025.0.0 (Eureka Client, Config) |
| Database | MySQL (운영) / H2 (테스트) |
| Data Access | Spring Data JPA |
| Store | Redis — Refresh Token·블랙리스트·교환 코드, Redisson 분산 락 |
| Auth | JWT (jjwt 0.12.5), OAuth2 Client |
| Build | Maven |

## 핵심 구현

- **Refresh Token Rotation** — Redis에 `jti`만 `@Id=memberId`로 저장, 재발급마다 회전하고 값이 다르면 세션 전체 무효화(재사용 탐지)
- **Redisson 분산 락** — 재발급 요청을 memberId 단위 `RLock`으로 직렬화, 20스레드 동시 요청 테스트로 성공 1건 검증
- **소셜 로그인 교환 코드** — 토큰 대신 60초 TTL 1회용 교환 코드를 URL로 전달(`POST /auth/oauth2/exchange`)
- **OAuth2 요청 Jackson 직렬화** — `OAuth2ClientJackson2Module`로 JSON 전환, 손상된 쿠키는 500 대신 `null` 처리
- **통합 예외 체계** — `ErrorCode` + `AuthException` + `GlobalExceptionHandler`, `X-Auth-Error` 헤더로 사유 구분
- **인증 정책 단일 소유** — 토큰 발급·회전·폐기는 이 서비스가 전담, 서명 검증은 [gateway](https://github.com/byesummer/trillion-books-gateway)가 직접 수행
