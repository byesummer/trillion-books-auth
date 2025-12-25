package com.nhnacademy.authservice.auth.jwt;

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
class JWTUtilTest {
    @Autowired
    private TestJwtProperties jwtProperities;

    private JWTUtil jwtUtil;
    @BeforeEach
    void setUp() {
        jwtUtil=new JWTUtil(jwtProperities.secret());
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

}