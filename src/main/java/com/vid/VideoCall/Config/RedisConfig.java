package com.vid.VideoCall.Config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.GenericToStringSerializer;
import org.springframework.data.redis.serializer.StringRedisSerializer;

@Configuration
public class RedisConfig {
    @Bean
    public RedisTemplate<String, Boolean> redisTemplate(RedisConnectionFactory redisConnectionFactory) {
        RedisTemplate<String, Boolean> redisTemplate = new RedisTemplate<>();
        redisTemplate.setConnectionFactory(redisConnectionFactory);

        // Set key serializer to StringRedisSerializer
        redisTemplate.setKeySerializer(new StringRedisSerializer());
        // Use GenericToStringSerializer to serialize Boolean values
        redisTemplate.setValueSerializer(new GenericToStringSerializer<>(Boolean.class));

        return redisTemplate;
    }
}
