package com.antonio.bootjwtmysql.config;

import com.antonio.bootjwtmysql.service.JwtUserDetailsService;
import io.jsonwebtoken.ExpiredJwtException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

// Extiende de OncePerRequestFilter.
// Este filtro será ejecutado para algunas peticiones
// chequea si la peticion tiene un token JWT valido.
// Si lo tiene, setea la autentificacion en el contexto para especificar que
// el usuario actual está autenticado

@Component
public class JwtRequestFilter extends OncePerRequestFilter {

    @Autowired
    private JwtUserDetailsService userDetailsService;

    @Autowired
    private JwtTokenUtil tokenUtil;


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        final String requestTokentHeader = request.getHeader("Authorization");

        String username = null;
        String jwtToken = null;

        System.out.println("TEST[JwtRequestFilter]: doFilter() --> "+requestTokentHeader);
        // Si existe el token en la cabecera y empieza por "Bearer",
        // retirale el Bearer y obten solo el token
        if (requestTokentHeader != null && requestTokentHeader.startsWith("Bearer ")) {

            jwtToken = requestTokentHeader.replace("Bearer ", "");
            System.out.println("TEST[JwtRequestFilter]: doFilter() --> if == true -->"+jwtToken);
            try {
                username = tokenUtil.getUsernameFromToken(jwtToken);
            }
            catch (IllegalArgumentException e ) {
                System.out.println("Unable to get JWT Token");
            }
            catch (ExpiredJwtException e){
                System.out.println("JWT Token has expired");
            }
        }
        else {
            logger.warn("JWT Token does not begin with Bearer String");
        }

        //Una vez tenemos el token, validamos
        if(username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(username);

            // si el token es valido, configura Spring Security
            if ((tokenUtil.validateToken(jwtToken, userDetails))) {
                UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(
                        userDetails, null, userDetails.getAuthorities());
                usernamePasswordAuthenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                // despuesr de setear la autenticacion en el contexto, tenemos
                // que especificar que el usuario actual está autenticado.
                SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
            }
        }
        filterChain.doFilter(request, response);
    }

}
