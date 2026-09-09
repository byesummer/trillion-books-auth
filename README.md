# trillion-books-auth

**Trillion** - MSA 기반 온라인 서점 플랫폼

- 인증/인가 서비스

## 기능

- Access/Refresh 이중 토큰 발급·검증
- OAuth2(Google·PAYCO) 소셜 로그인, 신규/기존 회원 분기
- 로그아웃 토큰 무효화 — Redis 블랙리스트
- 게이트웨이 위임 검증 — 다운스트림 서비스는 `X-Member-Id` / `X-Member-Role` 헤더만 신뢰

## 기술 스택

| 분류 | 스택                                                    |
|---|-------------------------------------------------------|
| Language | Java 21                                               |
| Framework | Spring Boot 3.5.7, Spring Security                    |
| Cloud | Spring Cloud 2025.0.0 (Eureka Client, Config)         |
| Database | MySQL (운영) / H2 (테스트)                                 |
| Data Access | Spring Data JPA                                       |
| Store | Redis — Refresh Token · 블랙리스트                         |
| Auth | JWT (jjwt 0.12.5), OAuth2 Client                      |
| Build | Maven                                                 |

## 핵심 설계 판단

### 1. 게이트웨이 위임 검증 + 헤더 신뢰 모델

다운스트림 서비스가 인증 코드·세션 설정을 갖지 않도록, 게이트웨이가 auth `/auth/validate`로 서명·만료·블랙리스트를 검증하고 `X-Member-Id` / `X-Member-Role`를 원본 요청에 주입한다. 각 서비스는 헤더만 신뢰한다(서비스는 외부 비노출, 게이트웨이가 유일 진입점).
게이트웨이·다운스트림은 별도 서비스이며, 이 서비스는 검증 API와 토큰 발급을 담당한다.

### 2. Stateless 토큰의 즉시 무효화 — Redis 블랙리스트

JWT는 만료 전까지 서명만 유효하면 통과하므로, 로그아웃 시 Access Token의 **잔여 유효시간을 TTL로 계산**해 Redis에 블랙리스트로 적재하고 검증 단계에서 조회한다. TTL이 토큰 만료 시점과 일치해 흔적이 자동 소멸한다.

### 3. OAuth2 공급자 응답 정규화

공급자마다 다른 사용자 정보 JSON을 `OAuth2Response` 구현체(`GoogleResponse` / `PaycoResponse`)로 표준 DTO에 매핑해, 인증 파이프라인 이후 단계는 공급자를 알지 못한다. `SocialLoginHandler`가 인증 직후 회원 상태를 분기하고, 신규 소셜 가입자에게 `ROLE_GUEST`를 부여해 추가정보 입력 페이지로 유도한다.