package com.trainingapi.trainingauth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;

@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {

    @Autowired
    private PasswordEncoder encoder;
    
    @Autowired
	private AuthenticationManager authenticationManager;

    @Autowired
    private UserDetailsService userDetailsService;

    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        
        // configurando o token de acesso
        clients
                .inMemory()
                .withClient("training-web")
                .secret(encoder.encode("web123"))
                .authorizedGrantTypes("password", "refresh_token")
                .scopes("write", "read")
                .accessTokenValiditySeconds(120)
                .refreshTokenValiditySeconds(1200)

                .and()

                // exemplo de uma autotização client_credentials, onde não há um resource owner
                .withClient("faturamento")
                .secret(encoder.encode("faturar123"))
                .authorizedGrantTypes("client_credentials")
                .scopes("write", "read")

                .and()
                .withClient("checktoken")
                .secret(encoder.encode("check123"))





                //url para autenticar:
                // http://localhost:8081/oauth/authorize?response_type=code&client_id=api_analytics&state=abc&redirect_uri=http://aplicacao-cliente
                .and()
                .withClient("api_analytics")
                .secret(encoder.encode("api123"))
                .authorizedGrantTypes("authorization_code")
                .scopes("write", "read")
                .redirectUris("http://aplicacao-cliente")


        ;




    }

    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
        security.checkTokenAccess("isAuthenticated()");
    }

    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        endpoints.authenticationManager(authenticationManager)
        .userDetailsService(userDetailsService)
        .reuseRefreshTokens(false);
    }

}
