package com.emma.Authentication.DTOs;

import java.time.LocalDateTime;

public record AuthMethodsResponse(
        boolean hasPassword,
        boolean hasGoogle,
        int totalMethods,
        LocalDateTime linkedAt
) {}