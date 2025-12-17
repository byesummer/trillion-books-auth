package com.nhnacademy.authservice.auth.entity;


import lombok.AllArgsConstructor;
import lombok.Getter;
import org.springframework.data.annotation.Id;
import org.springframework.data.redis.core.RedisHash;

//second
@RedisHash(value = "refreshToken", timeToLive = 86400)
@AllArgsConstructor
@Getter
public class RefreshToken {
    @Id
    private String refreshToken;

    private Long memberId;
    private String role;
}
