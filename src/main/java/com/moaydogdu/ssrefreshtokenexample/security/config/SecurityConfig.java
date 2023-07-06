package com.moaydogdu.ssrefreshtokenexample.security.config;

import com.moaydogdu.ssrefreshtokenexample.security.filter.JwtAuthenticationFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutHandler;

//role static imports.
import static com.moaydogdu.ssrefreshtokenexample.security.user.Role.ADMIN;
import static com.moaydogdu.ssrefreshtokenexample.security.user.Role.MANAGER;

//http methods static imports.
import static org.springframework.http.HttpMethod.DELETE;
import static org.springframework.http.HttpMethod.GET;
import static org.springframework.http.HttpMethod.POST;
import static org.springframework.http.HttpMethod.PUT;

//Permission static imports.
import static com.moaydogdu.ssrefreshtokenexample.security.user.Permission.ADMIN_CREATE;
import static com.moaydogdu.ssrefreshtokenexample.security.user.Permission.ADMIN_DELETE;
import static com.moaydogdu.ssrefreshtokenexample.security.user.Permission.ADMIN_UPDATE;
import static com.moaydogdu.ssrefreshtokenexample.security.user.Permission.ADMIN_READ;
import static com.moaydogdu.ssrefreshtokenexample.security.user.Permission.MANAGER_CREATE;
import static com.moaydogdu.ssrefreshtokenexample.security.user.Permission.MANAGER_DELETE;
import static com.moaydogdu.ssrefreshtokenexample.security.user.Permission.MANAGER_UPDATE;
import static com.moaydogdu.ssrefreshtokenexample.security.user.Permission.MANAGER_READ;


@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
@EnableMethodSecurity
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final AuthenticationProvider authenticationProvider;
    private final LogoutHandler logoutHandler;

    @Bean
    public SecurityFilterChain securityFilterChain(
            HttpSecurity httpSecurity
    ) throws Exception {

        httpSecurity
                .csrf().disable()

                .authorizeHttpRequests()

                .requestMatchers(
                        "/api/v1/auth/**"
                )
                .permitAll()

                .requestMatchers(
                        "/api/v1/stock/**"
                ).hasAnyRole(ADMIN.name(), MANAGER.name())

                .requestMatchers(GET, "/api/v1/stock/**").hasAnyAuthority(ADMIN_READ.name(), MANAGER_READ.name())
                .requestMatchers(POST, "/api/v1/stock/**").hasAnyAuthority(ADMIN_CREATE.name(), MANAGER_CREATE.name())
                .requestMatchers(PUT, "/api/v1/stock/**").hasAnyAuthority(ADMIN_UPDATE.name(), MANAGER_UPDATE.name())
                .requestMatchers(DELETE, "/api/v1/stock/**").hasAnyAuthority(ADMIN_DELETE.name(), MANAGER_DELETE.name())

                .anyRequest().authenticated()
                .and()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .authenticationProvider(authenticationProvider)
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .logout()
                .logoutUrl("/api/v1/auth/logout")
                .logoutSuccessUrl("www.google.com")
                .addLogoutHandler(logoutHandler)
                .logoutSuccessHandler((request, response, authentication) -> SecurityContextHolder.clearContext())
        ;

        return httpSecurity.build();


    }

}
