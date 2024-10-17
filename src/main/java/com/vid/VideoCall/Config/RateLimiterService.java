package com.vid.VideoCall.Config;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;
import java.util.concurrent.TimeUnit;

@Service
public class RateLimiterService {

    private final RedisTemplate<String, Integer> redisTemplate;
    private static final String RATE_LIMIT_PREFIX = "rate-limit:";
    private static final int REQUEST_LIMIT = 100; // 100 requests per time window
    private static final long TIME_WINDOW_IN_SECONDS = 60; // 1 minute window

    public RateLimiterService(@Qualifier("integerRedisTemplate") RedisTemplate<String, Integer> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    public boolean isAllowed(String clientId) {
        String key = RATE_LIMIT_PREFIX + clientId;
        Integer currentCount = redisTemplate.opsForValue().get(key);

        if (currentCount == null) {
            // Set initial count with an expiration for the time window
            redisTemplate.opsForValue().set(key, 1, TIME_WINDOW_IN_SECONDS, TimeUnit.SECONDS);
            return true;
        }

        if (currentCount < REQUEST_LIMIT) {
            // Increment the count and allow the request
            redisTemplate.opsForValue().increment(key);
            return true;
        } else {
            // Limit exceeded
            return false;
        }
    }
}
