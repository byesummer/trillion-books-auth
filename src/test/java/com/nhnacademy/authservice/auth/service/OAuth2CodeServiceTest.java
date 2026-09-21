package com.nhnacademy.authservice.auth.service;

import com.nhnacademy.authservice.auth.dto.TokenResponse;
import com.nhnacademy.authservice.auth.jwt.TokenIssuer;
import com.nhnacademy.authservice.global.error.exception.OAuthCodeInvalidException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
class OAuth2CodeServiceTest {

    @Mock
    private StringRedisTemplate redisTemplate;
    @Mock
    private ValueOperations<String, String> valueOperations;
    @Mock
    private TokenIssuer tokenIssuer;
    @InjectMocks
    private OAuth2CodeService oAuth2CodeService;

    @Test
    @DisplayName("issueCode 시 Redis에 저장하고 code를 반환한다.")
    void issueCodeAndReturnCode() {
        given(redisTemplate.opsForValue()).willReturn(valueOperations);

        String code = oAuth2CodeService.issueCode(1L, "MEMBER");

        ArgumentCaptor<String> keyCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> valueCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<Duration> ttlCaptor = ArgumentCaptor.forClass(Duration.class);
        verify(valueOperations).set(keyCaptor.capture(), valueCaptor.capture(), ttlCaptor.capture());

        assertThat(keyCaptor.getValue()).isEqualTo("oauth2code:" + code);
        assertThat(valueCaptor.getValue()).isEqualTo("1:MEMBER");
        assertThat(ttlCaptor.getValue()).isEqualTo(Duration.ofSeconds(60));
    }

    @Test
    @DisplayName("exchange 성공 시 code를 삭제하고 토큰을 발급한다.")
    void exchangeDeletesCodeAndIssuesToken() {
        String code = "test-code";
        given(valueOperations.get("oauth2code:" + code)).willReturn("1:MEMBER");
        given(redisTemplate.opsForValue()).willReturn(valueOperations);
        TokenResponse issued = new TokenResponse("access", "refresh");
        given(tokenIssuer.issue(1L, "MEMBER")).willReturn(issued);

        TokenResponse result = oAuth2CodeService.exchange(code);

        assertThat(result).isEqualTo(issued);
        verify(redisTemplate).delete("oauth2code:" + code);
    }

    @Test
    @DisplayName("존재하지 않는 code로 exchange하면 OAuthCodeInvalidException이 발생하고 토큰을 발급하지 않는다.")
    void exchangeWithUnknownCodeThrows() {
        given(redisTemplate.opsForValue()).willReturn(valueOperations);
        given(valueOperations.get(anyString())).willReturn(null);

        assertThatThrownBy(() -> oAuth2CodeService.exchange("bogus"))
                .isInstanceOf(OAuthCodeInvalidException.class);

        verify(tokenIssuer, never()).issue(anyLong(), anyString());
        verify(redisTemplate, never()).delete(anyString());
    }
}
