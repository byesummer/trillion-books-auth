package com.nhnacademy.authservice.global.config;

import com.nhnacademy.authservice.auth.jwt.SocialLoginHandler;
import com.nhnacademy.authservice.auth.service.CustomOAuth2UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final SocialLoginHandler socialLoginHandler;
    private final CustomOAuth2UserService customOAuth2UserService;
    private final StringRedisTemplate redisTemplate;

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) {
        return configuration.getAuthenticationManager();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) {

        http.csrf(AbstractHttpConfigurer::disable)
                .formLogin(AbstractHttpConfigurer::disable)
                .httpBasic(AbstractHttpConfigurer::disable)
                .logout(AbstractHttpConfigurer::disable);

        // 프레임 옵션 설정: 모든 URL의 프레임 보호 해제(X-Frame-Options를 비활성화)
        // h2 DB를 위해 dev 환경에서만 X-Frame-Options 임시 비활성화
        http.headers((headers) -> headers
                .frameOptions(HeadersConfigurer.FrameOptionsConfig::disable));

        // OAuth2 설정
        http.oauth2Login((oauth2) -> oauth2
                        .userInfoEndpoint((userInfo) -> userInfo
                                .userService(customOAuth2UserService))
                        .successHandler(socialLoginHandler)
        );

        // 소셜 로그인 문제로 주석 처리
        // OAuth2 로그인 과정에서 임시 세션 필요
//        http.sessionManagement((session) -> session
//                .sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        // 모든 요청 허용
        http.authorizeHttpRequests(auth ->
                auth.anyRequest().permitAll()
        );

        return http.build();
    }
}