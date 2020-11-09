package com.antonio.bootjwtmysql.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

// JwtTokenUtil es responsable de ejecutar operaciones JWT como la creacion y la validacion
// haciendo uso de io.jsonwebtoken.Jwts.
@Component
public class JwtTokenUtil {
    
    public static final long JWT_TOKEN_VALIDITY = 5 * 60 * 60;
    
    @Value("${jwt.secret}")
    private String secret;
    
    // Obtener el nombre de usuario del token jwt
    public String getUsernameFromToken(String token){
        return getClaimFromToken(token, Claims::getSubject);
    }

    public  <T> T getClaimFromToken(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = getAllClaimsFromToken(token);
        return claimsResolver.apply(claims);
    }

    // Obtiene toda la informacion del token que necesitaremos para la secret key
    private Claims getAllClaimsFromToken(String token) {
        return Jwts.parser().setSigningKey(secret).parseClaimsJws(token).getBody();
    }

    // genera el token para el usuario
    public String generateToken(UserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>();
        return doGenerateToken(claims, userDetails.getUsername());
    }

    private Boolean isTokenExpired(String token) {
        final Date expiration = getExpirationDateFromToken(token);
        return expiration.before(new Date());
    }

    private Date getExpirationDateFromToken(String token) {
        return getClaimFromToken(token, Claims::getExpiration);
    }

    // generamos el token
    private String doGenerateToken(Map<String, Object> claims, String username) {
        return Jwts.builder()
                //seteamos los campos del token
                .setClaims(claims)
                // seteamos el subject con el nombre de usuario
                .setSubject(username).setIssuedAt(new Date(System.currentTimeMillis()))
                // Seteamos el tiempo de expiracion del token
                .setExpiration(new Date(System.currentTimeMillis() + JWT_TOKEN_VALIDITY * 1000))
                //firmamos el token con la secretkey y lo compactamos
                .signWith(SignatureAlgorithm.HS512, secret).compact();
    }

    // validamos el token
    public Boolean validateToken(String token, UserDetails userDetails) {
        final String username = getUsernameFromToken(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }
}
