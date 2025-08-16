package com.jay.authify.filter;

import com.jay.authify.service.AppUserDetailsService;
import com.jay.authify.util.JwtUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

@Component
@RequiredArgsConstructor
public class JwtRequestFilter extends OncePerRequestFilter {

    private final AppUserDetailsService appUserDetailsService;
    private final JwtUtil jwtUtil;

    private static final List<String> PUBLIC_URLS = List.of("/login", "/register", "/send-reset-otp", "/reset-password","/logout");

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
       String path = request.getServletPath();
       if(PUBLIC_URLS.contains(path)) {
           filterChain.doFilter(request, response);
           return;
       }

       String jwt = null;
       String email = null;

       // 1. Check the Authorization Header
        final String authHeader = request.getHeader("Authorization");
        if(authHeader != null && authHeader.startsWith("Bearer ")) {
            jwt = authHeader.substring(7);
        }

        //2. If not Found in header, check cookies
        if(jwt == null) {
            Cookie[] cookie = request.getCookies();
            if(cookie != null) {
                for(Cookie c : cookie) {
                    if(c.getName().equals("jwt")) {
                       jwt = c.getValue();
                       break;
                    }
                }
            }
        }

        //3. Validate the token and set security context
        if(jwt != null) {
            email = jwtUtil.extractUsername(jwt);
            if(email != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                UserDetails userDetails = appUserDetailsService.loadUserByUsername(email);
                if(jwtUtil.validateToken(jwt, userDetails)) {
                    UsernamePasswordAuthenticationToken authenticationToken =
                            new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                    authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(authenticationToken);
                }
            }
        }


        filterChain.doFilter(request, response);

    }
}
