package com.vid.VideoCall.Config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.GenericToStringSerializer;
import org.springframework.data.redis.serializer.StringRedisSerializer;

@Configuration
public class RedisConfig {
    @Bean(name = "booleanRedisTemplate")
    public RedisTemplate<String, Boolean> booleanRedisTemplate(RedisConnectionFactory redisConnectionFactory) {
        RedisTemplate<String, Boolean> redisTemplate = new RedisTemplate<>();
        redisTemplate.setConnectionFactory(redisConnectionFactory);

        // Set key serializer to StringRedisSerializer
        redisTemplate.setKeySerializer(new StringRedisSerializer());
        // Use GenericToStringSerializer to serialize Boolean values
        redisTemplate.setValueSerializer(new GenericToStringSerializer<>(Boolean.class));

        return redisTemplate;
    }

    @Bean(name = "integerRedisTemplate")
    public RedisTemplate<String, Integer> integerRedisTemplate(RedisConnectionFactory redisConnectionFactory) {
        RedisTemplate<String, Integer> redisTemplate = new RedisTemplate<>();
        redisTemplate.setConnectionFactory(redisConnectionFactory);

        // Key will be serialized as string
        redisTemplate.setKeySerializer(new StringRedisSerializer());
        // Value will be serialized as integer for request counts
        redisTemplate.setValueSerializer(new GenericToStringSerializer<>(Integer.class));

        return redisTemplate;
    }
}
