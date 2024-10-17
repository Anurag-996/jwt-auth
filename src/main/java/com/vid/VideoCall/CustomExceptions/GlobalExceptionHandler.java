package com.vid.VideoCall.CustomExceptions;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.security.SignatureException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AccountStatusException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import java.net.URI;
import java.util.Map;

@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger logger = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    // Mapping exceptions to HTTP status codes
    private static final Map<Class<? extends Exception>, HttpStatus> EXCEPTION_STATUS_MAP = Map.of(
            BadCredentialsException.class, HttpStatus.UNAUTHORIZED,
            AuthenticationException.class, HttpStatus.UNAUTHORIZED,
            AccountStatusException.class, HttpStatus.FORBIDDEN,
            AccessDeniedException.class, HttpStatus.FORBIDDEN,
            SignatureException.class, HttpStatus.FORBIDDEN,
            ExpiredJwtException.class, HttpStatus.FORBIDDEN,
            TokenBlacklistedException.class, HttpStatus.UNAUTHORIZED);

    // Mapping exceptions to custom error descriptions
    private static final Map<Class<? extends Exception>, String> EXCEPTION_DESCRIPTION_MAP = Map.of(
            BadCredentialsException.class, "The username or password is incorrect.",
            AuthenticationException.class, "Authentication failed.",
            AccountStatusException.class, "The account is locked.",
            AccessDeniedException.class, "You are not authorized to access this resource.",
            SignatureException.class, "The JWT signature is invalid.",
            ExpiredJwtException.class, "The JWT token has expired.",
            TokenBlacklistedException.class, "The provided JWT token is blacklisted.");

    // Mapping exceptions to custom error types (URIs)
    private static final Map<Class<? extends Exception>, URI> EXCEPTION_TYPE_MAP = Map.of(
            BadCredentialsException.class, URI.create("urn:errors:bad-credentials"),
            AuthenticationException.class, URI.create("urn:errors:authentication-failed"),
            AccountStatusException.class, URI.create("urn:errors:account-locked"),
            AccessDeniedException.class, URI.create("urn:errors:access-denied"),
            SignatureException.class, URI.create("urn:errors:invalid-signature"),
            ExpiredJwtException.class, URI.create("urn:errors:token-expired"),
            TokenBlacklistedException.class, URI.create("urn:errors:blacklisted-token"));

    @ExceptionHandler(Exception.class)
    public ProblemDetail handleSecurityException(Exception exception) {
        // Log the exception (including stack trace)
        logException(exception);

        // Create and return a ProblemDetail response
        return createProblemDetail(exception);
    }

    private ProblemDetail createProblemDetail(Exception exception) {
        // Determine the HTTP status, description, and type based on the exception type
        HttpStatus status = EXCEPTION_STATUS_MAP.getOrDefault(exception.getClass(), HttpStatus.INTERNAL_SERVER_ERROR);
        String description = EXCEPTION_DESCRIPTION_MAP.getOrDefault(exception.getClass(), "Unexpected error occurred.");
        URI type = EXCEPTION_TYPE_MAP.getOrDefault(exception.getClass(), URI.create("urn:errors:unknown-error"));

        // Build and return the ProblemDetail object
        return buildProblemDetail(status, exception.getMessage(), description, type);
    }

    private ProblemDetail buildProblemDetail(HttpStatus status, String message, String description, URI type) {
        // Create a ProblemDetail object and set the relevant properties
        ProblemDetail problemDetail = ProblemDetail.forStatusAndDetail(status, message);
        problemDetail.setProperty("description", description);
        problemDetail.setType(type); // Set the error type

        return problemDetail;
    }

    private void logException(Exception exception) {
        // Log error details with the stack trace for troubleshooting
        logger.error("Exception caught: {}", exception.getMessage(), exception);
        // Stack trace logging
        exception.printStackTrace();
    }
}
