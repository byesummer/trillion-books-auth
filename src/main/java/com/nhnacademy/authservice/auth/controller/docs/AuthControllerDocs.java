package com.nhnacademy.authservice.auth.controller.docs;

import com.nhnacademy.authservice.auth.dto.LoginRequest;
import com.nhnacademy.authservice.auth.dto.TokenResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;

@Tag(name = "Auth", description = "인증 관련 API")
public interface AuthControllerDocs {

    @Operation(summary = "토큰 검증", description = "Access Token의 유효성을 검증하고 사용자 정보를 반환합니다.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "토큰 검증 성공 (헤더에 사용자 정보 포함)"),
            @ApiResponse(responseCode = "401", description = "유효하지 않은 토큰")
    })
    ResponseEntity<Void> validateToken(
            @Parameter(description = "Bearer Access Token", required = true)
            String authorizationHeader
    );

    @Operation(summary = "로그인", description = "이메일과 비밀번호로 로그인하여 Access Token과 Refresh Token을 발급받습니다.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "로그인 성공",
                    content = @Content(schema = @Schema(implementation = TokenResponse.class))),
            @ApiResponse(responseCode = "400", description = "잘못된 요청 데이터"),
            @ApiResponse(responseCode = "401", description = "아이디 또는 비밀번호 불일치"),
            @ApiResponse(responseCode = "403", description = "휴면 또는 탈퇴한 계정"),
            @ApiResponse(responseCode = "500", description = "서버 내부 오류")
    })
    ResponseEntity<?> login(
            @Parameter(description = "로그인 요청 데이터", required = true)
            @Valid @RequestBody LoginRequest request
    );

    @Operation(summary = "로그아웃", description = "Access Token을 블랙리스트에 추가하고 Redis에서 Refresh Token을 삭제합니다.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "로그아웃 성공")
    })
    ResponseEntity<Void> logout(
            @Parameter(description = "Bearer Access Token", required = true)
            String accessToken
    );

    @Operation(summary = "토큰 재발급", description = "Refresh Token을 사용하여 새로운 Access Token을 발급받습니다.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "토큰 재발급 성공",
                    content = @Content(schema = @Schema(implementation = TokenResponse.class))),
            @ApiResponse(responseCode = "401", description = "유효하지 않은 Refresh Token")
    })
    ResponseEntity<TokenResponse> reissue(
            @Parameter(description = "Refresh Token (Header: X-Refresh-Token)", required = true)
            String refreshToken
    );

    @Operation(summary = "회원 탈퇴", description = "회원 탈퇴 처리를 수행합니다.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "회원 탈퇴 성공")
    })
    ResponseEntity<Void> withdraw(
            @Parameter(description = "Member ID (Header: X-Member-Id)", required = true)
            Long memberId,
            @Parameter(description = "Refresh Token (Header: Refresh-Token)", required = false)
            String refreshToken
    );
}
