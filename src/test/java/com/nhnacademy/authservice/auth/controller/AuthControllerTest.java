package com.nhnacademy.authservice.auth.controller;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.doNothing;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nhnacademy.authservice.auth.dto.LoginRequest;
import com.nhnacademy.authservice.auth.dto.TokenResponse;
import com.nhnacademy.authservice.auth.service.AuthService;
import com.nhnacademy.authservice.global.error.exception.MemberStateConflictException;
import com.nhnacademy.authservice.member.entity.MemberState;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

@WebMvcTest(controllers = AuthController.class)
class AuthControllerTest {
    @Autowired
    private MockMvc mockMvc;
    @Autowired
    private ObjectMapper objectMapper;

    @MockitoBean
    private AuthService authService;

    @Test
    @DisplayName("토큰 검증 성공 시 회원 정보를 헤더에 담아 200 OK를 반환한다")
    void validateToken_success() throws Exception {
        // given
        String authHeader = "Bearer valid-token";
        Map<String, String> memberInfo = Map.of("memberId", "1", "role", "USER");
        given(authService.validateToken(authHeader)).willReturn(memberInfo);

        // when & then
        mockMvc.perform(post("/auth/validate")
                        .header(HttpHeaders.AUTHORIZATION, authHeader))
                .andExpect(status().isOk())
                .andExpect(header().string("X-Member-Id", "1"))
                .andExpect(header().string("X-Member-Role", "USER"));
    }

    @Test
    @DisplayName("로그인 성공 시 토큰 응답을 Body에 담아 반환한다")
    void login_success() throws Exception {
        // given
        LoginRequest request = new LoginRequest("test@test.com", "password123");
        TokenResponse response = new TokenResponse("access", "refresh");
        given(authService.login(any(LoginRequest.class))).willReturn(response);

        // when & then
        mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").value("access"))
                .andExpect(jsonPath("$.refreshToken").value("refresh"));
    }

    @Test
    @DisplayName("로그인 시 비밀번호가 틀리면 401 Unauthorized를 반환한다")
    void login_fail_bad_credentials() throws Exception {
        // given
        LoginRequest request = new LoginRequest("test@test.com", "wrong-password");
        given(authService.login(any(LoginRequest.class)))
                .willThrow(new BadCredentialsException("Bad credentials"));

        // when & then
        mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("휴면 계정 로그인 시 403 Forbidden과 전용 에러코드를 반환한다")
    void login_fail_dormant() throws Exception {
        // given
        LoginRequest request = new LoginRequest("dormant@test.com", "password");
        given(authService.login(any(LoginRequest.class)))
                .willThrow(new MemberStateConflictException("Dormant account", MemberState.DORMANT));

        // when & then
        mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("로그아웃 성공 시 200 OK를 반환한다")
    void logout_success() throws Exception {
        // given
        String authHeader = "Bearer valid-token";
        doNothing().when(authService).logout(authHeader);

        // when & then
        mockMvc.perform(post("/auth/logout")
                        .header(HttpHeaders.AUTHORIZATION, authHeader))
                .andExpect(status().isOk());
    }

    @Test
    @DisplayName("토큰 재발급 성공 시 새로운 토큰 세트를 반환한다")
    void reissue_success() throws Exception {
        // given
        String refreshToken = "old-refresh-token";
        TokenResponse response = new TokenResponse("new-access", "new-refresh");
        given(authService.reissue(refreshToken)).willReturn(response);

        // when & then
        mockMvc.perform(post("/auth/reissue")
                        .header("X-Refresh-Token", refreshToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").value("new-access"));
    }
}