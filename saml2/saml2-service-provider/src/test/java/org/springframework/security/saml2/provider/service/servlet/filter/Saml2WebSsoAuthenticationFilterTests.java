/*
 * Copyright 2002-2019 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.saml2.provider.service.servlet.filter;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;

import javax.servlet.http.HttpServletResponse;
import java.util.Base64;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

public class Saml2WebSsoAuthenticationFilterTests {

	private Saml2WebSsoAuthenticationFilter filter;
	private RelyingPartyRegistrationRepository repository = mock(RelyingPartyRegistrationRepository.class);
	private AuthenticationManager manager = mock(AuthenticationManager.class);
	private MockHttpServletRequest request = new MockHttpServletRequest();
	private HttpServletResponse response = new MockHttpServletResponse();

	@Rule
	public ExpectedException exception = ExpectedException.none();

	@Before
	public void setup() {
		filter = new Saml2WebSsoAuthenticationFilter(repository);
		filter.setAuthenticationManager(manager);
		request.setPathInfo("/login/saml2/sso/idp-registration-id");
		request.setParameter("SAMLResponse", new String(Base64.getEncoder().encode("xml-data".getBytes())));
	}

	@Test
	public void constructingFilterWithMissingRegistrationIdVariableThenThrowsException() {
		exception.expect(IllegalArgumentException.class);
		exception.expectMessage("filterProcessesUrl must contain a {registrationId} match variable");
		filter = new Saml2WebSsoAuthenticationFilter(repository, "/url/missing/variable");
	}

	@Test
	public void constructingFilterWithValidRegistrationIdVariableThenSucceeds() {
		filter = new Saml2WebSsoAuthenticationFilter(repository, "/url/variable/is/present/{registrationId}");
	}

	@Test
	public void requiresAuthenticationWhenHappyPathThenReturnsTrue() {
		Assert.assertTrue(filter.requiresAuthentication(request, response));
	}

	@Test
	public void requiresAuthenticationWhenCustomProcessingUrlThenReturnsTrue() {
		filter = new Saml2WebSsoAuthenticationFilter(repository, "/some/other/path/{registrationId}");
		request.setPathInfo("/some/other/path/idp-registration-id");
		request.setParameter("SAMLResponse", "xml-data-goes-here");
		Assert.assertTrue(filter.requiresAuthentication(request, response));
	}

	@Test
	public void attemptAuthenticationAlsoSetsAuthenticationDetails() {
		given(repository.findByRegistrationId(any())).willReturn(mock(RelyingPartyRegistration.class));
		filter.setAuthenticationDetailsSource((request) -> "details");
		filter.attemptAuthentication(request, response);
		verify(manager).authenticate(argThat(argument -> argument.getDetails() == "details"));
	}


}
