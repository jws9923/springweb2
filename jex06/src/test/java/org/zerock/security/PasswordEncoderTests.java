package org.zerock.security;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import lombok.Setter;
import lombok.extern.log4j.Log4j;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes = {
		org.zerock.config.RootConfig.class,
		org.zerock.config.SecurityConfig.class } )
@Log4j
public class PasswordEncoderTests {

	@Setter(onMethod_ = {@Autowired})
	private PasswordEncoder pwEncoder;

	@Test
	public void testEncode() {
		
		String str = "member";
		
		String enStr = pwEncoder.encode(str);
		
		//$2a$10$yJl/xKnd3D9mkhk4SiSmzOnRnIBE9WHx3uWImwcSkQ.abnkeFViPW
		log.info(enStr);
		
	}
}


