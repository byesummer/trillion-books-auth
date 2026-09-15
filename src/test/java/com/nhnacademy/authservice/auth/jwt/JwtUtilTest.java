package com.nhnacademy.authservice.auth.jwt;

import com.nhnacademy.authservice.global.error.exception.TokenExpiredException;
import com.nhnacademy.authservice.global.error.exception.TokenInvalidException;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit.jupiter.SpringExtension;

@ExtendWith(SpringExtension.class)
@EnableConfigurationProperties(value = {TestJwtProperties.class})
@TestPropertySource("classpath:application-jwt.properties")
class JwtUtilTest {
    @Autowired
    private TestJwtProperties jwtProperities;

    private JwtUtil jwtUtil;
    @BeforeEach
    void setUp() {
        jwtUtil=new JwtUtil(jwtProperities.secret());
    }
    @Test
    @DisplayName("유효기간이 지난 토큰은 예외를 반환한다.")
    void isExpired() {
        Assertions.assertThatThrownBy(()->jwtUtil.validateAccessToken(jwtProperities.timeOutAccessToken())).isInstanceOf(RuntimeException.class);
    }
    @Test
    @DisplayName("null인 토큰은 검증하면 예외반환한다.")
    void isExpire2d() {
        Assertions.assertThatThrownBy(()->jwtUtil.validateAccessToken(null)).isInstanceOf(RuntimeException.class);
    }
    @Test
    @DisplayName("유효기한이 있는 리프레쉬 토큰에서 액세스토큰 검증하면 예외합니다.")
    void isExpire213() {
        Assertions.assertThatThrownBy(()->jwtUtil.validateAccessToken(jwtProperities.rightRefreshToken())).isInstanceOf(RuntimeException.class);
    }


    @Test
    @DisplayName("유효기간이 지나지 않는 액세스 토큰에서 액세스토큰 검증하면 예외를 반환하지않음.")
    void isExpired1() {
        Assertions.assertThatCode(()->jwtUtil.validateAccessToken(jwtProperities.rightAccessToken())).doesNotThrowAnyException();
    }

    @Test
    @DisplayName("유효기간이 지난 리프레쉬 토큰은 만기가 된다.")
    void isExpired10() {
        Assertions.assertThatThrownBy(()->jwtUtil.validateRefreshToken(jwtProperities.timeOutRefreshToken())).isInstanceOf(RuntimeException.class);
    }
    @Test
    @DisplayName("null인 리프레쉬 토큰은 만기가 된다.")
    void isExpired11() {
        Assertions.assertThatThrownBy(()->jwtUtil.validateRefreshToken(null)).isInstanceOf(RuntimeException.class);
    }
    @Test
    @DisplayName("리프레쉬 토큰아니면 리프레검증에선 예외를 반환.")
    void isExpired12() {
        Assertions.assertThatThrownBy(()->jwtUtil.validateRefreshToken(jwtProperities.rightAccessToken())).isInstanceOf(RuntimeException.class);
    }

    @Test
    @DisplayName("만기가 지나지 않은 리프레쉬 토큰이면, 리프레검증에선 예외를 반환하지않음.")
    void isExpired14() {
        Assertions.assertThatCode(()->jwtUtil.validateRefreshToken(jwtProperities.rightRefreshToken())).doesNotThrowAnyException();
    }

    @Test
    @DisplayName("만료된 액세스 토큰은 TokenExpiredException을 던진다.")
    void 만료_토큰은_TokenExpiredException() {
        Assertions.assertThatThrownBy(() -> jwtUtil.validateAccessToken(jwtProperities.timeOutAccessToken()))
                .isInstanceOf(TokenExpiredException.class);
    }

    @Test
    @DisplayName("깨진 문자열 토큰은 TokenInvalidException을 던진다.")
    void 깨진_문자열은_TokenInvalidException() {
        Assertions.assertThatThrownBy(() -> jwtUtil.validateAccessToken("garbage"))
                .isInstanceOf(TokenInvalidException.class);
    }

    @Test
    @DisplayName("다른 시크릿으로 서명된 토큰은 TokenInvalidException을 던진다.")
    void 서명_불일치는_TokenInvalidException() {
        JwtUtil otherSecretJwtUtil = new JwtUtil("other-secret-please-change-0123456789abcdef");
        String foreignToken = otherSecretJwtUtil.createJwt(1L, TokenKinds.ACCESS_TOKEN, "MEMBER");

        Assertions.assertThatThrownBy(() -> jwtUtil.validateAccessToken(foreignToken))
                .isInstanceOf(TokenInvalidException.class);
    }
}