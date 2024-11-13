package com.example.springjwt.config;

import com.example.springjwt.jwt.CustomLogoutFilter;
import com.example.springjwt.jwt.JWTFilter;
import com.example.springjwt.jwt.JWTUtil;
import com.example.springjwt.jwt.CustomLoginFilter;
import com.example.springjwt.repository.RefreshRepository;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import java.util.Collections;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final AuthenticationConfiguration authenticationConfiguration;
    private final JWTUtil jwtUtil;
    private final RefreshRepository refreshRepository;

    public SecurityConfig(AuthenticationConfiguration authenticationConfiguration, JWTUtil jwtUtil, RefreshRepository refreshRepository) {

        this.authenticationConfiguration = authenticationConfiguration;
        this.jwtUtil = jwtUtil;
        this.refreshRepository = refreshRepository;
    }

    //AuthenticationManager Bean 등록
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {

        return configuration.getAuthenticationManager();
    }

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        http
                .cors((cors) -> cors
                        .configurationSource(new CorsConfigurationSource() {
                            @Override
                            public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {
                                CorsConfiguration configuration = new CorsConfiguration();
                                /*
                                http://localhost:3000에서 오는 요청만 허용합니다.
                                프론트엔드 애플리케이션이 이 포트에서 실행 중임을 의미합니다.
                                여러 출처를 허용하려면 List에 추가 URL을 포함시킬 수 있습니다.
                                */
                                configuration.setAllowedOrigins(Collections.singletonList("http://localhost:3000"));
                                /*
                                *는 모든 HTTP 메서드(GET, POST, PUT, DELETE 등)를 허용한다는 의미입니다.
                                특정 메서드만 허용하고 싶다면 Arrays.asList("GET", "POST")와 같이 지정할 수 있습니다.
                                 */
                                configuration.setAllowedMethods(Collections.singletonList("*"));
                                /*
                                쿠키나 Authorization 헤더와 같은 자격 증명을 포함한 요청을 허용합니다.
                                이 설정은 보안상 중요하므로, 신뢰할 수 있는 출처에만 true로 설정해야 합니다.
                                 */
                                configuration.setAllowCredentials(true);
                                /*
                                클라이언트가 보낼 수 있는 모든 종류의 헤더를 허용합니다.
                                특정 헤더만 허용하고 싶다면 명시적으로 리스트에 추가할 수 있습니다.
                                 */
                                configuration.setAllowedHeaders(Collections.singletonList("*"));
                                /*
                                프리플라이트 요청(OPTIONS)의 결과를 캐시하는 시간을 3600초(1시간)로 설정합니다.
                                이는 불필요한 프리플라이트 요청을 줄여 성능을 향상시킵니다.
                                */
                                configuration.setMaxAge(3600L);
                                /*
                                클라이언트에서 접근할 수 있는 응답 헤더를 지정합니다.
                                여기서는 "Authorization" 헤더를 클라이언트에 노출시킵니다.
                                JWT 토큰과 같은 인증 정보를 주고받을 때 필요합니다.
                                 */
                                configuration.setExposedHeaders(Collections.singletonList("Authorization"));


                                return configuration;
                            }
                        }));

        //csrf disable
        http
                .csrf((auth) -> auth.disable());

        //form login disable
        http
                .formLogin((auth) -> auth.disable());

        //http basic disable
        http
                .httpBasic((auth) -> auth.disable());

        http
                .authorizeHttpRequests((auth) -> auth
                        .requestMatchers("/login", "/", "/join").permitAll()
                        .requestMatchers("/admin").hasRole("ADMIN")
                        .requestMatchers("/reissue").permitAll()
                        .anyRequest().authenticated());

        http
                .addFilterBefore(new JWTFilter(jwtUtil), CustomLoginFilter.class);

        http
                .addFilterAt(new CustomLoginFilter(authenticationManager(authenticationConfiguration), jwtUtil, refreshRepository), UsernamePasswordAuthenticationFilter.class);

        http
                .addFilterBefore(new CustomLogoutFilter(jwtUtil, refreshRepository), LogoutFilter.class);

        //session 설정
        http
                .sessionManagement((session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)));
        return http.build();
    }

}
