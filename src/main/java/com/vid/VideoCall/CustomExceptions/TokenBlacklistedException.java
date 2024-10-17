package com.vid.VideoCall.CustomExceptions;

import jakarta.servlet.ServletException;

public class TokenBlacklistedException extends ServletException {
    public TokenBlacklistedException(String message) {
        super(message);
    }
}