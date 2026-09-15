package com.nhnacademy.authservice.auth.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.nhnacademy.authservice.auth.dto.CustomUserDetails;
import com.nhnacademy.authservice.auth.dto.LoginRequest;
import com.nhnacademy.authservice.auth.dto.TokenResponse;
import com.nhnacademy.authservice.auth.jwt.JwtUtil;
import com.nhnacademy.authservice.auth.jwt.TokenIssuer;
import com.nhnacademy.authservice.auth.repository.RefreshTokenRepository;
import com.nhnacademy.authservice.global.error.exception.TokenBlacklistedException;
import com.nhnacademy.authservice.global.error.exception.TokenExpiredException;
import com.nhnacademy.authservice.member.entity.Member;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.springframework.data.redis.RedisConnectionFailureException;
import com.nhnacademy.authservice.member.entity.MemberRole;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    @Mock private AuthenticationManager authenticationManager;
    @Mock private JwtUtil jwtUtil;
    @Mock private RefreshTokenRepository refreshTokenRepository;
    @Mock private StringRedisTemplate redisTemplate;
    @Mock private TokenParser tokenParser;
    @Mock private TokenIssuer tokenIssuer;
    @Mock private ValueOperations<String, String> valueOperations;

    @InjectMocks
    private AuthService authService;

    @Nested
    @DisplayName("로그인 테스트")
    class LoginTest {
        @Test
        @DisplayName("로그인 성공 시 토큰 응답을 반환한다")
        void login_success() {
            // given
            LoginRequest request = new LoginRequest("test@test.com", "password");
            Member member = mock(Member.class);
            CustomUserDetails principal = mock(CustomUserDetails.class);
            Authentication auth = mock(Authentication.class);

            when(authenticationManager.authenticate(any())).thenReturn(auth);
            when(auth.getPrincipal()).thenReturn(principal);
            when(principal.getMember()).thenReturn(member);
            when(member.getMemberId()).thenReturn(1L);
            when(member.getMemberRole()).thenReturn(MemberRole.MEMBER);
            when(tokenIssuer.issue(1L, "MEMBER"))
                    .thenReturn(new TokenResponse("access-token", "refresh-token"));

            // when
            TokenResponse response = authService.login(request);

            // then
            assertThat(response.accessToken()).isEqualTo("access-token");
            assertThat(response.refreshToken()).isEqualTo("refresh-token");
            verify(tokenIssuer).issue(1L, "MEMBER");
            verify(member).setMemberLatestLoginAt(any());
        }
    }

    @Nested
    @DisplayName("토큰 검증 테스트")
    class ValidateTokenTest {
        @Test
        @DisplayName("유효한 토큰인 경우 memberId와 role을 반환한다")
        void validateToken_success() {
            // given
            String header = "Bearer valid-token";
            when(tokenParser.getToken(header)).thenReturn("valid-token");
            when(redisTemplate.hasKey("BL:valid-token")).thenReturn(false);
            when(jwtUtil.getMemberId("valid-token")).thenReturn(1L);
            when(jwtUtil.getRole("valid-token")).thenReturn("USER");

            // when
            Map<String, String> result = authService.validateToken(header);

            // then
            assertThat(result.get("memberId")).isEqualTo("1");
            assertThat(result.get("role")).isEqualTo("USER");
        }

        @Test
        @DisplayName("블랙리스트에 등록된 토큰이면 예외가 발생한다")
        void validateToken_blacklisted() {
            // given
            String header = "Bearer blacklisted-token";
            when(tokenParser.getToken(header)).thenReturn("blacklisted-token");
            when(redisTemplate.hasKey("BL:blacklisted-token")).thenReturn(true);

            // when & then
            assertThatThrownBy(() -> authService.validateToken(header))
                    .isInstanceOf(TokenBlacklistedException.class);
        }
    }

    @Nested
    @DisplayName("로그아웃 테스트")
    class LogoutTest {
        @Test
        @DisplayName("로그아웃 시 액세스 토큰을 Redis 블랙리스트에 등록한다")
        void logout_success() {
            // given
            String header = "Bearer token";
            String token = "token";
            long expirationTime = System.currentTimeMillis() + 100000;

            when(tokenParser.getToken(header)).thenReturn(token);
            when(jwtUtil.getExpiration(token)).thenReturn(expirationTime);
            when(redisTemplate.opsForValue()).thenReturn(valueOperations);

            // when
            authService.logout(header);

            // then
            verify(valueOperations).set(
                    eq("BL:" + token),
                    eq("logout"),
                    anyLong(),
                    eq(TimeUnit.MILLISECONDS)
            );
        }

        @Test
        @DisplayName("만료된 액세스 토큰으로 로그아웃해도 RT 세션은 정리된다 (블랙리스트 적재만 스킵)")
        void logout_expiredAccessToken_stillDeletesSession() {
            // given
            String header = "Bearer expired-token";
            String token = "expired-token";
            Claims claims = Jwts.claims().subject("1").build();
            when(tokenParser.getToken(header)).thenReturn(token);
            when(jwtUtil.getMemberId(token)).thenThrow(new TokenExpiredException(claims));

            // when
            authService.logout(header);

            // then
            verify(refreshTokenRepository).deleteById(1L);
            verify(redisTemplate, never()).opsForValue();
        }

        @Test
        @DisplayName("Redis 장애로 블랙리스트 적재가 실패하면 예외가 전파된다 (조용히 200을 반환하지 않는다)")
        void logout_RedisFailure_propagates() {
            // given
            String header = "Bearer token";
            String token = "token";
            long expirationTime = System.currentTimeMillis() + 100000;

            when(tokenParser.getToken(header)).thenReturn(token);
            when(jwtUtil.getExpiration(token)).thenReturn(expirationTime);
            when(redisTemplate.opsForValue()).thenReturn(valueOperations);
            doThrow(new RedisConnectionFailureException("Redis down"))
                    .when(valueOperations).set(anyString(), anyString(), anyLong(), any());

            // when & then
            assertThatThrownBy(() -> authService.logout(header))
                    .isInstanceOf(RedisConnectionFailureException.class);
        }
    }
}