package com.nhnacademy.authservice.auth.oauth2;

import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;

import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class HttpCookieOAuth2AuthorizationRequestRepositoryTest {

    private final HttpCookieOAuth2AuthorizationRequestRepository repository =
            new HttpCookieOAuth2AuthorizationRequestRepository();

    @Test
    @DisplayName("직렬화 후 역직렬화하면 원본과 동일한 요청을 복원한다")
    void serializeThenDeserializeRestoresOriginal() {
        OAuth2AuthorizationRequest original = OAuth2AuthorizationRequest.authorizationCode()
                .authorizationUri("https://provider.com/oauth2/authorize")
                .clientId("client-id")
                .redirectUri("https://front.trillion-book.shop/login/oauth2/code/provider")
                .scopes(Set.of("email"))
                .state("state-value")
                .build();

        MockHttpServletResponse saveResponse = new MockHttpServletResponse();
        repository.saveAuthorizationRequest(original, new MockHttpServletRequest(), saveResponse);

        String setCookieHeader = saveResponse.getHeader("Set-Cookie");
        String[] nameValue = setCookieHeader.substring(0, setCookieHeader.indexOf(';')).split("=", 2);
        MockHttpServletRequest loadRequest = new MockHttpServletRequest();
        loadRequest.setCookies(new Cookie(nameValue[0], nameValue[1]));

        OAuth2AuthorizationRequest result = repository.loadAuthorizationRequest(loadRequest);

        assertThat(result).isNotNull();
        assertThat(result.getAuthorizationUri()).isEqualTo(original.getAuthorizationUri());
        assertThat(result.getClientId()).isEqualTo(original.getClientId());
        assertThat(result.getRedirectUri()).isEqualTo(original.getRedirectUri());
        assertThat(result.getScopes()).isEqualTo(original.getScopes());
        assertThat(result.getState()).isEqualTo(original.getState());
    }

    @Test
    @DisplayName("JSON으로 파싱되지 않는 값이 담긴 쿠키는 null을 반환한다")
    void deserializeWithBrokenJsonReturnsNull() {
        String brokenJsonBase64 = java.util.Base64.getUrlEncoder()
                .encodeToString("not-a-json-object".getBytes());
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setCookies(new Cookie(
                HttpCookieOAuth2AuthorizationRequestRepository.OAUTH2_AUTHORIZATION_REQUEST_COOKIE_NAME,
                brokenJsonBase64));

        assertThat(repository.loadAuthorizationRequest(request)).isNull();
    }

    @Test
    @DisplayName("base64 자체가 깨진 쿠키는 null을 반환한다")
    void deserializeWithInvalidBase64ReturnsNull() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setCookies(new Cookie(
                HttpCookieOAuth2AuthorizationRequestRepository.OAUTH2_AUTHORIZATION_REQUEST_COOKIE_NAME,
                "!!!not-valid-base64!!!"));

        assertThat(repository.loadAuthorizationRequest(request)).isNull();
    }
}
