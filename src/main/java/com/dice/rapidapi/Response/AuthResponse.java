package com.dice.rapidapi.Response;

import lombok.Data;

@Data
public class AuthResponse {
    private String jwt;
    private boolean status;
}
