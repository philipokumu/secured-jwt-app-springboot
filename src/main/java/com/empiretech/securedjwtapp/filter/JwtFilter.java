package com.empiretech.securedjwtapp.filter;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.empiretech.securedjwtapp.Util.JwtUtil;
import com.empiretech.securedjwtapp.service.CustomUserDetailsService;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

@Component // This componen
public class JwtFilter extends OncePerRequestFilter {

    @Autowired
    private JwtUtil jwtUtil;
    @Autowired
    private CustomUserDetailsService service;

    @Override
    protected void doFilterInternal(HttpServletRequest httpServletRequest, HttpServletResponse HttpServletResponse, FilterChain filterChain)
            throws ServletException, IOException {

                String authorizationHeader = httpServletRequest.getHeader("Authorization");
                String token = null;
                String username = null;
                
                // Extract username from token
                if (authorizationHeader != null && authorizationHeader.startsWith("bearer")) {
                    token = authorizationHeader.substring(7);
                    username = jwtUtil.extractUsername(token);
                }

                // Validate username
                if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                    UserDetails userDetails = service.loadUserByUsername(username);
                    // If token is valid
                    if (jwtUtil.validateToken(token, userDetails)) {

                        //Validate userdetail fetched from db
                        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken =
                            new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                        
                        // If user detail is valid, set it to security context holder
                        usernamePasswordAuthenticationToken
                        .setDetails(new WebAuthenticationDetailsSource().buildDetails(httpServletRequest));
                        SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
                    }
                }
                filterChain.doFilter(httpServletRequest, HttpServletResponse);

    }
    
}
