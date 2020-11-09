package com.antonio.bootjwtmysql.model;

import java.io.Serializable;

public class JwtResponse implements Serializable {

    private final String JwtToken;

    public JwtResponse(String jwtToken) {
        JwtToken = jwtToken;
    }

    public String getJwtToken() {
        return JwtToken;
    }
}
