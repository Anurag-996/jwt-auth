package com.vid.VideoCall.Config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import com.vid.VideoCall.Jwt.JwtAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

        private final DaoAuthenticationProvider daoAuthenticationProvider;
        private final RedisRateLimitingFilter redisRateLimitingFilter;
        private final JwtAuthenticationFilter jwtAuthenticationFilter;

        public SecurityConfig(DaoAuthenticationProvider daoAuthenticationProvider,
                        RedisRateLimitingFilter redisRateLimitingFilter,
                        JwtAuthenticationFilter jwtAuthenticationFilter) {
                this.daoAuthenticationProvider = daoAuthenticationProvider;
                this.redisRateLimitingFilter = redisRateLimitingFilter;
                this.jwtAuthenticationFilter = jwtAuthenticationFilter;
        }

        @Bean
        public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
                http.csrf(csrf -> csrf.disable()) // Disable CSRF (replace with your CSRF configuration if needed)
                                .authorizeHttpRequests(auth -> auth
                                                .requestMatchers("/auth/signup", "/auth/login", "/api/v1/users/getAll")
                                                .permitAll()
                                                .anyRequest().authenticated())
                                .sessionManagement(session -> session
                                                .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                                .logout(logout -> logout
                                                .logoutUrl("/logout")
                                                .logoutSuccessUrl("/login?logout")
                                                .invalidateHttpSession(true)
                                                .deleteCookies("JSESSIONID"))
                                .authenticationProvider(daoAuthenticationProvider)
                                .addFilterBefore(redisRateLimitingFilter, UsernamePasswordAuthenticationFilter.class)
                                .addFilterBefore(jwtAuthenticationFilter,
                                                UsernamePasswordAuthenticationFilter.class);

                return http.build();
        }
}
