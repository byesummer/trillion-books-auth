package com.nhnacademy.authservice.global.config;

import com.nhnacademy.authservice.auth.jwt.SocialLoginHandler;
import com.nhnacademy.authservice.auth.oauth2.HttpCookieOAuth2AuthorizationRequestRepository;
import com.nhnacademy.authservice.auth.service.CustomOAuth2UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final SocialLoginHandler socialLoginHandler;
    private final CustomOAuth2UserService customOAuth2UserService;
    private final HttpCookieOAuth2AuthorizationRequestRepository cookieAuthorizationRequestRepository;

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception { // Exception 추가 필요

        http.csrf(AbstractHttpConfigurer::disable)
                .formLogin(AbstractHttpConfigurer::disable)
                .httpBasic(AbstractHttpConfigurer::disable)
                .logout(AbstractHttpConfigurer::disable);

        http.headers((headers) -> headers
                .frameOptions(HeadersConfigurer.FrameOptionsConfig::disable));

        http.sessionManagement((session) -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        http.oauth2Login((oauth2) -> oauth2
                // 인증 요청을 쿠키에 저장하도록 설정
                .authorizationEndpoint(authorization -> authorization
                        .baseUri("/oauth2/authorization")
                        .authorizationRequestRepository(cookieAuthorizationRequestRepository))
                .userInfoEndpoint((userInfo) -> userInfo
                        .userService(customOAuth2UserService))
                .successHandler(socialLoginHandler)
        );

        http.authorizeHttpRequests(auth ->
                auth.anyRequest().permitAll()
        );

        return http.build();
    }
}