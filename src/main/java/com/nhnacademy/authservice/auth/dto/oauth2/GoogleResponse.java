package com.nhnacademy.authservice.auth.dto.oauth2;

import java.util.Map;

public class GoogleResponse implements OAuth2Response {
    private final Map<String, Object> attribute;

    public GoogleResponse(Map<String, Object> attribute) {
        this.attribute = attribute;
    }

    @Override
    public String getProvider() {
        return "google";
    }

    @Override
    public String getProviderId() {
        Object sub = attribute.get("sub");
        return (sub != null) ? sub.toString() : null;
    }

    @Override
    public String getEmail() {
        Object email = attribute.get("email");
        return (email != null) ? email.toString() : null;
    }

    @Override
    public String getName() {
        Object name = attribute.get("name");
        return (name != null) ? name.toString() : null;
    }
}