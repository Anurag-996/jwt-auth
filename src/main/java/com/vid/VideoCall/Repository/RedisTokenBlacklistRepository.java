package com.vid.VideoCall.Repository;

import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Repository;
import java.util.concurrent.TimeUnit;

@Slf4j
@Repository
public class RedisTokenBlacklistRepository {

    private static final String BLACKLIST_PREFIX = "blacklist:";

    private final RedisTemplate<String, Boolean> redisTemplate;

    public RedisTokenBlacklistRepository(RedisTemplate<String, Boolean> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    public void save(String token, long expirationTimeInMillis) {
        try {
            redisTemplate.opsForValue().set(BLACKLIST_PREFIX + token, true, expirationTimeInMillis, TimeUnit.MILLISECONDS);
        } catch (Exception e) {
            log.error("Error saving token to Redis", e);
            throw new RuntimeException("Failed to save token to blacklist", e);
        }
    }

    public boolean exists(String token) {
        try {
            Boolean isBlacklisted = redisTemplate.opsForValue().get(BLACKLIST_PREFIX + token);
            return isBlacklisted != null && isBlacklisted;
        } catch (Exception e) {
            log.error("Error checking token in Redis", e);
            throw new RuntimeException("Failed to check token in blacklist", e);
        }
    }
}
