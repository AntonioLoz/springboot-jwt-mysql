package com.antonio.bootjwtmysql.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;


/**
 * @EnableWebSecurity permite que Spring encuentre y aplique automaticamente la clase de seguridad global
 * @EnableGlobalMethodSecurity proporciona seguridad AOP en metodos. Esto habilita a @PreAuthorize y
 * @postAuthorize para controles de autorizacion previos o posteriores a la invocacion para por
 * ejemplo el control de autorizacion.
 *
 * Vamos a sobreescribir el metodo configure(HttpSecurity http) de la interface
 * WebSecurityConfigurerAdapter Esto le dice a spring security como vamos a configurar CORS y CSRF,
 * si queramos exigir que todos los usuarios esten autenticados o no, el cual filtró JwtTokenFilter,
 * y cuando queremos que funcione (Antes de UsernamePasswordAuthenticationFilter) y que excepcion manejaremos
 * (JwtAuthenticationEntryPoint).
 *
 * Spring Security cargará los detalles de usuario para hacer la autorizacion y la autenticacion. Esto implica el
 * uso de UserDetailsService el cual implementamos en JwtUserDetailsService
 *
 * JwtUserDetailsService(UserDetailsService) será usada para configurar DaoAuthenticationProvider
 * mediante el uso del metodo AuthenticationManagerBuilder.userDetailsService(). Tambien
 * necesitaremos un passwordEncoder. Si no especificamos el passwordEncoder usará texto plano.
 *
 */

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private JwtAuthenticationEntryPoint entryPoint;

    @Autowired
    private UserDetailsService detailsService;

    @Autowired
    private JwtRequestFilter filter;

    // Configuramos AuthenticationManager para que sepa
    // desde donde cargamos las credenciales de usuario
    // para el match. Usaremos BCryptPasswordEncoder
    @Override
    public void configure(AuthenticationManagerBuilder managerBuilder) throws Exception {
        managerBuilder.userDetailsService(detailsService).passwordEncoder(this.passwordEncoder());
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Override
    protected void configure(HttpSecurity httpSecurity) throws Exception {
        // Deshabilitamos CSRF
        httpSecurity.csrf().disable()
                // no necesitamos autenticacion en
                .authorizeRequests().antMatchers("/authenticate", "/register").permitAll()
                // todas las demas peticiones necesitan auth
                .anyRequest().authenticated().and()
                // nos aseguramos de que es una sesion sin estado ya que no la vamos a usar
                .exceptionHandling().authenticationEntryPoint(entryPoint).and().sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        //Añade un filtro para validar el token de toda peticion
        httpSecurity.addFilterBefore(this.filter, UsernamePasswordAuthenticationFilter.class);
    }
}
