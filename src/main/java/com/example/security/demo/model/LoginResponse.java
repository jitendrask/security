package com.example.security.demo.model;

import java.util.List;

public record LoginResponse(String jwtToken, String username, List<String> roles) {}
