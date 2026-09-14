package com.nhnacademy.authservice.auth.service;

import com.nhnacademy.authservice.TestSecurityConfig;
import com.nhnacademy.authservice.auth.dto.TokenResponse;
import com.nhnacademy.authservice.auth.jwt.TokenIssuer;
import com.nhnacademy.authservice.global.error.exception.InvalidRefreshTokenException;
import com.nhnacademy.authservice.global.error.exception.LockAcquisitionException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
@Import(TestSecurityConfig.class)
class AuthServiceConcurrencyTest {

    @Autowired
    private AuthService authService;
    @Autowired
    private TokenIssuer tokenIssuer;

    @Test
    @DisplayName("같은 RT로 동시에 재발급 요청해도 정확히 1건만 성공한다")
    void concurrentReissue_onlyOneSucceeds() throws InterruptedException {
        // 실제 로그인 상태 재현 (mock 아님, 진짜 Redis에 세션 저장)
        TokenResponse initial = tokenIssuer.issue(1L, "MEMBER");
        String refreshToken = initial.refreshToken();

        int threadCount = 20;
        ExecutorService executor = Executors.newFixedThreadPool(threadCount);
        CountDownLatch readyLatch = new CountDownLatch(threadCount);
        CountDownLatch startLatch = new CountDownLatch(1);
        CountDownLatch doneLatch = new CountDownLatch(threadCount);

        AtomicInteger successCount = new AtomicInteger();
        List<TokenResponse> successResponses = Collections.synchronizedList(new ArrayList<>());

        for (int i = 0; i < threadCount; i++) {
            executor.submit(() -> {
                readyLatch.countDown();
                try {
                    startLatch.await();
                    TokenResponse response = authService.reissue(refreshToken);
                    successCount.incrementAndGet();
                    successResponses.add(response);
                } catch (InvalidRefreshTokenException | LockAcquisitionException e) {
                    // 예상된 실패 — 재사용 탐지 또는 락 대기 초과
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                } finally {
                    doneLatch.countDown();
                }
            });
        }

        readyLatch.await();
        startLatch.countDown();
        doneLatch.await();
        executor.shutdown();

        assertThat(successCount.get()).isEqualTo(1);
        assertThat(successResponses.get(0).accessToken()).isNotBlank();
        assertThat(successResponses.get(0).refreshToken()).isNotBlank();
    }

    @Test
    @DisplayName("서로 다른 회원의 재발급은 락 경합 없이 병렬로 처리된다")
    void concurrentReissue_differentMembers_runInParallel() throws InterruptedException {
        int memberCount = 10;
        List<String> refreshTokens = Collections.synchronizedList(new ArrayList<>());
        for (long memberId = 1; memberId <= memberCount; memberId++) {
            refreshTokens.add(tokenIssuer.issue(memberId, "MEMBER").refreshToken());
        }

        ExecutorService executor = Executors.newFixedThreadPool(memberCount);
        CountDownLatch readyLatch = new CountDownLatch(memberCount);
        CountDownLatch startLatch = new CountDownLatch(1);
        CountDownLatch doneLatch = new CountDownLatch(memberCount);
        AtomicInteger successCount = new AtomicInteger();

        long startedAt = System.nanoTime();
        for (String rt : refreshTokens) {
            executor.submit(() -> {
                readyLatch.countDown();
                try {
                    startLatch.await();
                    authService.reissue(rt);
                    successCount.incrementAndGet();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                } finally {
                    doneLatch.countDown();
                }
            });
        }

        readyLatch.await();
        startLatch.countDown();
        doneLatch.await();
        long elapsedMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startedAt);
        executor.shutdown();

        assertThat(successCount.get()).isEqualTo(memberCount);
        // memberId 단위 락이라 서로 경합하지 않는다 — 전역 락이었다면 순차 처리로 훨씬 오래 걸렸을 구간
        assertThat(elapsedMs).isLessThan(3000);
    }
}
