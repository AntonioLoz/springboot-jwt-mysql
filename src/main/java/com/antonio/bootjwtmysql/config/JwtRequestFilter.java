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
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 *
 * Extiende de OncePerRequestFilter.
 * Este filtro será ejecutado para algunas peticiones
 * chequea si la peticion tiene un token JWT valido.
 * Mediante el uso JwtToken.getUsernameFromToken() obtiene el username del token,
 * carga el UserDetails desde el JwtUserDetailsService por medio del username.
 * Una vez obtiene el UserDetails, por medio de JwtTokenUtil.validateToken(token, userDetails),
 * valida la autenticacion, crea un objeto UsernamePasswordAuthenticationToken y lo publica
 * en el contexto de seguridad.
 *
 */

@Component
public class JwtRequestFilter extends OncePerRequestFilter {

    @Autowired
    private JwtUserDetailsService userDetailsService;

    @Autowired
    private JwtTokenUtil tokenUtil;


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        // Extraemos el token del header request
        final String requestTokentHeader = request.getHeader("Authorization");

        String username = null;
        String jwtToken = null;

        // Si existe el token en la cabecera y empieza por "Bearer",
        // retirale el Bearer y obten solo el token
        if (requestTokentHeader != null && requestTokentHeader.startsWith("Bearer ")) {

            jwtToken = requestTokentHeader.replace("Bearer ", "");
            try {
                // obtenemos el nombre de usuario del token recibido y manejamos las excepciones por si las hubiese
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

        //Una vez tenemos el username, comprobamos si hay alguna autenticacion el el securityContext y si no hay, validamos
        if(username != null && SecurityContextHolder.getContext().getAuthentication() == null) {

            UserDetails userDetails = this.userDetailsService.loadUserByUsername(username);

            // si el token es valido, configura Spring Security
            if (tokenUtil.validateToken(jwtToken, userDetails)) {
                // Creamos la clase Authentication
                UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                        userDetails, null, userDetails.getAuthorities());
                authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                // despuesr de setear la autenticacion en el contexto, tenemos
                // que especificar que el usuario actual está autenticado.
                SecurityContextHolder.getContext().setAuthentication(authenticationToken);
            }
        }
        filterChain.doFilter(request, response);
    }

}
