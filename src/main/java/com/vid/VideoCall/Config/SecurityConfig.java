package com.vid.VideoCall.Config;

import com.vid.VideoCall.Jwt.JwtAuthenticationFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final DaoAuthenticationProvider daoAuthenticationProvider;
    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final RedisRateLimitingFilter redisRateLimitingFilter;

    public SecurityConfig(JwtAuthenticationFilter jwtAuthenticationFilter,
            DaoAuthenticationProvider daoAuthenticationProvider,
            RedisRateLimitingFilter redisRateLimitingFilter) {
        this.daoAuthenticationProvider = daoAuthenticationProvider;
        this.jwtAuthenticationFilter = jwtAuthenticationFilter;
        this.redisRateLimitingFilter = redisRateLimitingFilter;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
            http.csrf(csrf -> csrf.disable()) // Disable CSRF (replace with your CSRF configuration if needed)
                            .authorizeHttpRequests(auth -> auth
                                            .requestMatchers("/auth/login", "/auth/signup", "/api/v1/users/getAll")
                                            .permitAll() // Permit specific endpoints
                                            .anyRequest().authenticated()) // Authenticate all other requests
                            .sessionManagement(
                                            session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)) // Stateless
                                                                                                                       // session
                                                                                                                       // management
                            .logout(logout -> logout
                                            .logoutUrl("/auth/logout")
                                            .logoutSuccessUrl("/login?logout")
                                            .invalidateHttpSession(true)
                                            .deleteCookies("JSESSIONID"))
                            .authenticationProvider(daoAuthenticationProvider)
                            .addFilterBefore(redisRateLimitingFilter, UsernamePasswordAuthenticationFilter.class)
                            .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

            return http.build();
    }

}
