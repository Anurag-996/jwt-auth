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
            MissingTokenException.class, HttpStatus.UNAUTHORIZED,
            TokenBlacklistedException.class, HttpStatus.UNAUTHORIZED);

    // Mapping exceptions to custom error descriptions
    private static final Map<Class<? extends Exception>, String> EXCEPTION_DESCRIPTION_MAP = Map.of(
            BadCredentialsException.class, "The username or password is incorrect.",
            AuthenticationException.class, "Authentication failed.",
            AccountStatusException.class, "The account is locked.",
            AccessDeniedException.class, "You are not authorized to access this resource.",
            SignatureException.class, "The JWT signature is invalid.",
            ExpiredJwtException.class, "The JWT token has expired.",
            MissingTokenException.class, "The Authorization token is required but was not provided.",
            TokenBlacklistedException.class, "The provided JWT token is blacklisted.");

    @ExceptionHandler(Exception.class)
    public ProblemDetail handleSecurityException(Exception exception) {
        // Log the exception (including stack trace)
        logException(exception);

        // Create a ProblemDetail response
        ProblemDetail errorDetail = createProblemDetail(exception);

        if (errorDetail == null) {
            errorDetail = ProblemDetail.forStatusAndDetail(HttpStatus.INTERNAL_SERVER_ERROR,
                    "An unexpected error occurred.");
            errorDetail.setProperty("description", "Unknown internal server error.");
        }

        return errorDetail;
    }

    private ProblemDetail createProblemDetail(Exception exception) {
        // Determine the HTTP status and description based on the exception type
        HttpStatus status = EXCEPTION_STATUS_MAP.getOrDefault(exception.getClass(), HttpStatus.INTERNAL_SERVER_ERROR);
        String description = EXCEPTION_DESCRIPTION_MAP.getOrDefault(exception.getClass(), "Unexpected error occurred.");

        return buildProblemDetail(status, exception.getMessage(), description);
    }

    private ProblemDetail buildProblemDetail(HttpStatus status, String message, String description) {
        // Build and return the ProblemDetail object
        ProblemDetail problemDetail = ProblemDetail.forStatusAndDetail(status, message);
        problemDetail.setProperty("description", description);
        return problemDetail;
    }

    private void logException(Exception exception) {
        // Log error details with the stack trace for troubleshooting
        logger.error("Exception caught: {}", exception.getMessage(), exception);
        // Stack trace logging
        exception.printStackTrace();
    }

    @ExceptionHandler(MissingTokenException.class)
    public ProblemDetail handleMissingTokenException(MissingTokenException exception) {
        // Log the exception
        logger.error("Missing token exception: {}", exception.getMessage());

        // Create ProblemDetail response for MissingTokenException
        ProblemDetail errorDetail = ProblemDetail.forStatusAndDetail(HttpStatus.UNAUTHORIZED, exception.getMessage());
        errorDetail.setProperty("description", "The Authorization token is required but was not provided.");
        return errorDetail;
    }

}
