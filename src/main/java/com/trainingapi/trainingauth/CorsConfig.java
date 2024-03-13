package com.trainingapi.trainingauth;

import java.util.Collections;

import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

@Configuration
public class CorsConfig {

    @Bean
    public FilterRegistrationBean<CorsFilter> corsFilter() {
        // Cria uma nova configuração de CORS.
        CorsConfiguration config = new CorsConfiguration();

    // Define que o servidor permitirá credenciais durante as solicitações de CORS.
        config.setAllowCredentials(true);

    // Define os origens permitidos para solicitações CORS como todos ("*").
        config.setAllowedOrigins(Collections.singletonList("*"));

    // Define os métodos HTTP permitidos para solicitações CORS como todos ("*").
        config.setAllowedMethods(Collections.singletonList("*"));

    // Define os cabeçalhos HTTP permitidos para solicitações CORS como todos ("*").
        config.setAllowedHeaders(Collections.singletonList("*"));

    // Cria uma fonte de configuração baseada em URL para a configuração CORS.
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();

    // Registra a configuração CORS criada anteriormente para o caminho "/oauth/token".
        source.registerCorsConfiguration("/oauth/token", config);

    // Cria um bean de registro de filtro para o filtro CORS.
        FilterRegistrationBean<CorsFilter> bean = new FilterRegistrationBean<>();

    // Define o filtro CORS com a fonte de configuração CORS criada anteriormente.
        bean.setFilter(new CorsFilter(source));

    // Define a ordem de precedência do filtro CORS como a mais alta, garantindo que ele seja executado antes de outros filtros.
        bean.setOrder(Ordered.HIGHEST_PRECEDENCE);

    // Retorna o bean de registro de filtro configurado para a aplicação.
        return bean;

    }

}
