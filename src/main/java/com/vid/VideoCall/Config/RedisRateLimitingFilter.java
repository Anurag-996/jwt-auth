package com.vid.VideoCall.Config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import java.io.IOException;

@Component
public class RedisRateLimitingFilter extends OncePerRequestFilter {

    private final RateLimiterService rateLimiterService;

    public RedisRateLimitingFilter(RateLimiterService rateLimiterService) {
        this.rateLimiterService = rateLimiterService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        // Extract client IP address (handle proxy headers if behind a reverse proxy)
        String clientIp = getClientIp(request);

        // Check if the rate limit is exceeded
        if (!rateLimiterService.isAllowed(clientIp)) {
            response.setStatus(429); // 429 Too Many Requests
            response.setHeader("Retry-After", "60"); // Optional: Inform client when to retry (in seconds)
            response.getWriter().write("Too many requests. Please try again later.");
            return;
        }

        // If allowed, proceed to the next filter or controller
        filterChain.doFilter(request, response);
    }

    // Method to handle proxy-aware IP extraction
    private String getClientIp(HttpServletRequest request) {
        String clientIp = request.getHeader("X-Forwarded-For");
        if (clientIp == null || clientIp.isEmpty() || "unknown".equalsIgnoreCase(clientIp)) {
            clientIp = request.getHeader("X-Real-IP");
        }
        if (clientIp == null || clientIp.isEmpty() || "unknown".equalsIgnoreCase(clientIp)) {
            clientIp = request.getRemoteAddr();
        }
        return clientIp.split(",")[0].trim(); // Handle multiple IPs in X-Forwarded-For
    }
}
