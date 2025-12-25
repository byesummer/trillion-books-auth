package com.nhnacademy.authservice.auth.service;

import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class TokenParserTest {
    private TokenParser tokenParser;
    private static final String secret = "Bearer ";
    @BeforeEach
    void setUp() {
        tokenParser = new TokenParser();
    }
    @Test
    @DisplayName("널이면 예외반환.")
    void getToken() {
        Assertions.assertThatThrownBy(()->tokenParser.getToken(null)).isInstanceOf(RuntimeException.class);
    }
    @ParameterizedTest
    @ValueSource(strings = {" ","qwe","asd","Auth","bearer "})
    @DisplayName("시크릿에 맞지않으면 예외 반환")
    void getToken1(String header) {
        Assertions.assertThatThrownBy(()->tokenParser.getToken(header)).isInstanceOf(RuntimeException.class);
    }

    @ParameterizedTest
    @ValueSource(strings = {" ","qwe","asd","Auth","bearer "})
    @DisplayName("시크릿이 앞에있으면 예외 반환하지않는다.")
    void getToken2(String header) {
        Assertions.assertThatCode(()->tokenParser.getToken(secret+header)).doesNotThrowAnyException();
    }
}