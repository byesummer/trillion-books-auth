package com.nhnacademy.authservice.auth.service;

import com.nhnacademy.authservice.auth.dto.oauth2.CustomOAuth2User;
import com.nhnacademy.authservice.auth.dto.oauth2.GoogleResponse;
import com.nhnacademy.authservice.auth.dto.oauth2.OAuth2Response;
import com.nhnacademy.authservice.auth.dto.oauth2.PaycoResponse;
import com.nhnacademy.authservice.member.entity.Member;
import com.nhnacademy.authservice.member.entity.MemberRole;
import com.nhnacademy.authservice.member.entity.MemberState;
import com.nhnacademy.authservice.member.repository.MemberRepository;
import com.nhnacademy.authservice.global.error.exception.OAuthEmailNotFoundException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.time.LocalDate;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    private final MemberRepository memberRepository;
    private final PasswordEncoder passwordEncoder;

    private final RestTemplate restTemplate = new RestTemplate();

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {

        String registrationId = userRequest.getClientRegistration().getRegistrationId();
        Map<String, Object> attributes;

        if ("payco".equals(registrationId)) {
            log.info("Processing Payco Login...");
            attributes = getPaycoAttributes(userRequest);
        } else {
            OAuth2User oAuth2User = super.loadUser(userRequest);
            attributes = oAuth2User.getAttributes();
        }

        log.info("OAuth2 User Attributes: {}", attributes);

        OAuth2Response oAuth2Response;
        if (registrationId.equals("google")) {
            oAuth2Response = new GoogleResponse(attributes);
        } else if (registrationId.equals("payco")) {
            oAuth2Response = new PaycoResponse(attributes);
        } else {
            return null;
        }

        String memberEmail = oAuth2Response.getEmail();
        if (memberEmail == null || memberEmail.isBlank()) {
            throw new OAuthEmailNotFoundException("이메일을 찾을 수 없습니다.");
        }

        // DB에서 이메일로 조회
        Optional<Member> existMember = memberRepository.findByMemberEmail(memberEmail);

        if (existMember.isPresent()) {
            // 기존 회원이면 해당 역할로 로그인
            return new CustomOAuth2User(oAuth2Response, "ROLE_" + existMember.get().getMemberRole().name());
        } else {
            // 신규 회원이면 회원가입 처리 (GUEST)
            Member newMember = Member.builder()
                    .memberEmail(memberEmail)
                    .memberPassword(passwordEncoder.encode(UUID.randomUUID().toString()))
                    .memberName(oAuth2Response.getName())
                    .memberBirth(LocalDate.of(1000, 1, 1))
                    .memberContact(null)
                    .memberState(MemberState.ACTIVE)
                    .memberLatestLoginAt(LocalDate.now())
                    .memberRole(MemberRole.GUEST)
                    .memberPoint(0)
                    .memberAccumulateAmount(0)
                    .memberOauthId(oAuth2Response.getProviderId())
                    .gradeId(1L)
                    .build();

            memberRepository.save(newMember);

            return new CustomOAuth2User(oAuth2Response, "ROLE_GUEST");
        }
    }

    private Map<String, Object> getPaycoAttributes(OAuth2UserRequest userRequest) {
        String userInfoUri = userRequest.getClientRegistration().getProviderDetails().getUserInfoEndpoint().getUri();
        String accessToken = userRequest.getAccessToken().getTokenValue();
        String clientId = userRequest.getClientRegistration().getClientId();

        HttpHeaders headers = new HttpHeaders();
        headers.add("client_id", clientId);
        headers.add("access_token", accessToken);
        headers.setContentType(MediaType.APPLICATION_JSON);

        HttpEntity<String> entity = new HttpEntity<>(headers);

        try {
            ResponseEntity<Map<String, Object>> response = restTemplate.exchange(
                    userInfoUri,
                    HttpMethod.POST,
                    entity,
                    new ParameterizedTypeReference<Map<String, Object>>() {}
            );
            return response.getBody();
        } catch (Exception e) {
            log.error("Payco UserInfo Request Failed", e);
            throw new OAuth2AuthenticationException("Payco UserInfo Request Failed");
        }
    }
}