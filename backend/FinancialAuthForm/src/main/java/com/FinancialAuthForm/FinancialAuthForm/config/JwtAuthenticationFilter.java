package com.FinancialAuthForm.FinancialAuthForm.config;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.FinancialAuthForm.FinancialAuthForm.token.TokenRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.beans.Transient;
import java.io.IOException;
import java.security.Security;

import jakarta.transaction.TransactionScoped;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

  private final JwtService jwtService;
  private final UserDetailsService userDetailsService;
  private final TokenRepository tokenRepository;
  private static final Logger logger = LoggerFactory.getLogger(JwtAuthenticationFilter.class);

  @Override
  protected void doFilterInternal(
      @NonNull HttpServletRequest request,
      @NonNull HttpServletResponse response,
      @NonNull FilterChain filterChain
  ) throws ServletException, IOException {
    logger.info("JwtAuthenticationFilter is executing for request: {}", request.getRequestURI());
    if (request.getServletPath().matches("/api/v1/auth/(login|register)")) {
      filterChain.doFilter(request, response);
      logger.info("This is being triggered for login or register");
      return;
    }
    final String authHeader = request.getHeader("Authorization");

    final String jwt;
    final String userEmail;
    if (authHeader == null ||!authHeader.startsWith("Bearer ")) {
      filterChain.doFilter(request, response);
      logger.info("check1");
      return;
    }

    logger.info("\n\nFirst Checks\n\n");
    logger.info("AuthHeader = {}", authHeader.substring(0));
    jwt = authHeader.substring(7);
    userEmail = jwtService.extractUsername(jwt);
    logger.info("\nPass1\n");
    if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {
      logger.info("\nPass2\n");
      UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);


      logger.info("\n\nToken is being checked\n\n");

      if (jwtService.isTokenValid(jwt, userDetails)) {

        logger.info("\n\nToken is Valid\n\n");

        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
            userDetails,
            null,
            userDetails.getAuthorities()
        );
        authToken.setDetails(
            new WebAuthenticationDetailsSource().buildDetails(request)
        );
        SecurityContextHolder.getContext().setAuthentication(authToken);
      }
      logger.info("\nfail1\n");
    }
    logger.info("\nfail2\n");
    filterChain.doFilter(request, response);
    logger.info("\nfail3\n");
  }
}