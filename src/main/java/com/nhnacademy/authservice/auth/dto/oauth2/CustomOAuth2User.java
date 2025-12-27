package com.nhnacademy.authservice.auth.dto.oauth2;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Map;

@RequiredArgsConstructor
public class CustomOAuth2User implements OAuth2User {

    private final OAuth2Response oAuth2Response;
    private final String role; // ROLE_MEMBER or ROLE_GUEST

    @Override
    public Map<String, Object> getAttributes() { return Collections.emptyMap(); }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        Collection<GrantedAuthority> collection = new ArrayList<>();
        collection.add((GrantedAuthority) () -> role);
        return collection;
    }

    @Override
    public String getName() {return oAuth2Response.getProviderId();}
    public String getEmail() { return oAuth2Response.getEmail(); }
}