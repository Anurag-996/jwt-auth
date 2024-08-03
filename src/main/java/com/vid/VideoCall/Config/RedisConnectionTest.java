package com.vid.VideoCall.Config;

import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

@Component
public class RedisConnectionTest {

    @Autowired
    private StringRedisTemplate stringRedisTemplate;

    @PostConstruct
    public void testConnection() {
        try {
            stringRedisTemplate.opsForValue().set("test", "connected");
            String value = stringRedisTemplate.opsForValue().get("test");
            System.out.println("Redis connection successful, test value: " + value);
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Failed to connect to Redis");
        }
    }
}
