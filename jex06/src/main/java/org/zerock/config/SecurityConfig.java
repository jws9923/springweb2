package org.zerock.config;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;
import org.zerock.security.CustomLoginSuccessHandler;
import org.zerock.security.CustomUserDetailsService;

import lombok.Setter;
import lombok.extern.log4j.Log4j;

@Configuration
@EnableWebSecurity
@Log4j
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	@Setter(onMethod_ = { @Autowired })
	private DataSource dataSource;

	@Bean
	public UserDetailsService customUserService() {
		return new CustomUserDetailsService();
	}

	// in custom userdetails
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {

		auth.userDetailsService(customUserService()).passwordEncoder(passwordEncoder());
	}

	// @Override
	// protected void configure(AuthenticationManagerBuilder auth) throws Exception
	// {
	// log.info("configure JDBC ............................");
	//
	// String queryUser = "select userid , userpw , enabled from tbl_member where
	// userid = ? ";
	// String queryDetails = "select userid, auth from tbl_member_auth where userid
	// = ? ";
	//
	// auth.jdbcAuthentication().dataSource(dataSource).passwordEncoder(passwordEncoder())
	// .usersByUsernameQuery(queryUser).authoritiesByUsernameQuery(queryDetails);
	// }

	@Bean
	public AuthenticationSuccessHandler loginSuccessHandler() {
		return new CustomLoginSuccessHandler();
	}

	@Override
	public void configure(HttpSecurity http) throws Exception {

		http.authorizeRequests()
		.antMatchers("/sample/all").permitAll()
		.antMatchers("/sample/admin")
		.access("hasRole('ROLE_ADMIN')")
		.antMatchers("/sample/member")
		.access("hasRole('ROLE_MEMBER')");

		http.formLogin()
		.loginPage("/customLogin")
		.loginProcessingUrl("/login")
		.successHandler(loginSuccessHandler());

		http.logout()
		.logoutUrl("/customLogout")
		.invalidateHttpSession(true)
		.deleteCookies("remember-me","JSESSION_ID");
		
		http.rememberMe()
	      .key("zerock")
	      .tokenRepository(persistentTokenRepository())
	      .tokenValiditySeconds(604800);


	}

	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Bean
	public PersistentTokenRepository persistentTokenRepository() {
		JdbcTokenRepositoryImpl repo = new JdbcTokenRepositoryImpl();
		repo.setDataSource(dataSource);
		return repo;
	}

}
