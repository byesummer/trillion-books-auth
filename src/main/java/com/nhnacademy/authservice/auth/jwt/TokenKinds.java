package com.nhnacademy.authservice.auth.jwt;

import lombok.Getter;

@Getter
public enum TokenKinds {
    ACCESS_TOKEN(1800000L),// 30분
    REFRESH_TOKEN(86400000L);// 24시간
    private final Long expiredTime;

    TokenKinds(Long expiredTime) {
        this.expiredTime = expiredTime;
    }
}
