package com.trainingapi.trainingauth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.CompositeTokenGranter;
import org.springframework.security.oauth2.provider.TokenGranter;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.redis.RedisTokenStore;

import java.util.Arrays;

@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {

    @Autowired
    private PasswordEncoder encoder;
    
    @Autowired
	private AuthenticationManager authenticationManager;

    @Autowired
    private UserDetailsService userDetailsService;

    @Autowired
    private RedisConnectionFactory redisConnectionFactory;

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
                .secret(encoder.encode(""))
                .authorizedGrantTypes("authorization_code")
                .scopes("write", "read")
                .redirectUris("http://127.0.0.1:5500", "http://aplicacao-cliente")


                // url pra autenticar no implicit grant type
                // http://localhost:8081/oauth/authorize?response_type=token&client_id=webadmin&state=abc&redirect_uri=http://aplicacao-cliente
                .and()
                .withClient("webadmin")
                .scopes("write", "read")
                .authorizedGrantTypes("implicit")
                .redirectUris("http://aplicacao-cliente");

                 //  URL para autenticar usando pkace com code_challange_plain
                //http://localhost:8081/oauth/authorize?response_type=code&client_id=api_analytics&state&redirect_uri=http://aplicacao-cliente&code_challenge=teste123&code_challenge_method=plain
                // gerando com s256
                //http://localhost:8081/oauth/authorize?response_type=code&client_id=api_analytics&redirect_uri=http://aplicacao-cliente&code_challenge=teste123&code_challenge_method=s256




    }

    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
        security.checkTokenAccess("isAuthenticated()").allowFormAuthenticationForClients();
    }

    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        endpoints.authenticationManager(authenticationManager)
        .userDetailsService(userDetailsService)
        .reuseRefreshTokens(false)
        .tokenStore(redisTokenStore())
        .tokenGranter(tokenGranter(endpoints));
    }

    private TokenStore redisTokenStore() {
        return  new RedisTokenStore(redisConnectionFactory);
    }

    private TokenGranter tokenGranter(AuthorizationServerEndpointsConfigurer endpoints) {
        var pkceAuthorizationCodeTokenGranter = new PkceAuthorizationCodeTokenGranter(endpoints.getTokenServices(),
                endpoints.getAuthorizationCodeServices(), endpoints.getClientDetailsService(),
                endpoints.getOAuth2RequestFactory());

        var granters = Arrays.asList(
                pkceAuthorizationCodeTokenGranter, endpoints.getTokenGranter());

        return new CompositeTokenGranter(granters);
    }

}
