package com.vid.VideoCall.Jwt;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.servlet.HandlerExceptionResolver;
import com.vid.VideoCall.CustomExceptions.MissingTokenException;
import com.vid.VideoCall.CustomExceptions.TokenBlacklistedException;
import java.io.IOException;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final HandlerExceptionResolver handlerExceptionResolver;
    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;

    public JwtAuthenticationFilter(HandlerExceptionResolver handlerExceptionResolver, JwtService jwtService,
            UserDetailsService userDetailsService) {
        this.handlerExceptionResolver = handlerExceptionResolver;
        this.jwtService = jwtService;
        this.userDetailsService = userDetailsService;
    }

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain) throws ServletException, IOException {

        try {
            final String authHeader = request.getHeader("Authorization");

            // Check if the Authorization header is missing or invalid
            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                throw new MissingTokenException("Authorization token is missing.");
            }

            // Variables for JWT and user email
            final String jwt = authHeader.substring(7);
            final String userEmail = jwtService.extractUsername(jwt);

            // Check if the token is blacklisted
            if (jwtService.isTokenBlacklisted(jwt)) {
                throw new TokenBlacklistedException("Token is blacklisted");
            }

            // Check if the user is already authenticated
            if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);

                // Validate the JWT token against the user details
                if (jwtService.isTokenValid(jwt, userDetails)) {
                    // Create and set the authentication token in the security context
                    UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                            userDetails,
                            null,
                            userDetails.getAuthorities());

                    authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(authToken);
                }
            }
        } catch (MissingTokenException exception) {
            // Handle the MissingTokenException
            handlerExceptionResolver.resolveException(request, response, null, exception);
            return;
        } catch (TokenBlacklistedException exception) {
            // Handle the TokenBlacklistedException
            handlerExceptionResolver.resolveException(request, response, null, exception);
            return;
        } catch (Exception exception) {
            // Handle any other exceptions
            handlerExceptionResolver.resolveException(request, response, null, exception);
            return;
        }

        // Continue the filter chain
        filterChain.doFilter(request, response);
    }
}
