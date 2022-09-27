/******************************************************************************
 * Copyright (C) 2016 Logilite Technologies LLP								  *
 * This program is free software; you can redistribute it and/or modify it    *
 * under the terms version 2 of the GNU General Public License as published   *
 * by the Free Software Foundation. This program is distributed in the hope   *
 * that it will be useful, but WITHOUT ANY WARRANTY; without even the implied *
 * warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.           *
 * See the GNU General Public License for more details.                       *
 * You should have received a copy of the GNU General Public License along    *
 * with this program; if not, write to the Free Software Foundation, Inc.,    *
 * 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA.                     *
 *****************************************************************************/
package com.logilite.sso.azure.principle;

import java.io.IOException;
import java.text.ParseException;
import java.util.Date;
import java.util.Map;
import java.util.logging.Level;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.adempiere.webui.sso.ISSOPrinciple;
import org.compiere.model.I_SSO_PrincipleConfig;
import org.compiere.model.MSysConfig;
import org.compiere.util.CLogger;
import org.compiere.util.Language;

import com.microsoft.aad.msal4j.IAuthenticationResult;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;

/**
 * Microsoft Azure AD SSO login and authentication
 * 
 * @author Logilite Technologies
 */
public class SSOMicrosoftAzure implements ISSOPrinciple
{
	/** Logger */
	protected static CLogger		log				= CLogger.getCLogger(SSOMicrosoftAzure.class);
	AuthHelper authHelper = null;

	public SSOMicrosoftAzure(I_SSO_PrincipleConfig config)
	{
		authHelper = new AuthHelper(config);
	}

	@Override
	public boolean hasAuthenticationCode(HttpServletRequest request, HttpServletResponse response)
	{
		Map<String, String[]> httpParameters = request.getParameterMap();
		boolean containIdToken = httpParameters.containsKey("id_token");
		boolean containsCode = httpParameters.containsKey("code");

		return containIdToken || containsCode;
	}

	@Override
	public void getAuthenticationToken(HttpServletRequest request, HttpServletResponse response) throws Throwable
	{
		if (SessionManagementHelper.getAuthSessionObject(request) != null)
			return;
		
		String currentUri = request.getRequestURL().toString();
		if(request.getHeader("X-Forwarded-Host")!=null)
		{	
			log.fine("Old uri:" + currentUri);
			currentUri = authHelper.getRedirectURIs();
			log.fine("Replace URI:" +  currentUri);
		}
		log.log(Level.FINE,"CurrentURI:" + currentUri);
		log.log(Level.FINE,"X-Forwarded-Host:" + request.getHeader("X-Forwarded-Host"));

		
		
		String queryStr = request.getQueryString();
		String fullUrl = currentUri + (queryStr != null ? "?" + queryStr : "");
		authHelper.processAuthenticationCodeRedirect(request, currentUri, fullUrl);
		((HttpServletResponse) response).sendRedirect(currentUri);
	}

	@Override
	public boolean isAuthenticated(HttpServletRequest request, HttpServletResponse response)
	{
		if (request.getSession() == null)
			return false;
		return request.getSession().getAttribute(ISSOPrinciple.SSO_PRINCIPLE_SESSION_NAME) != null;
	}

	@Override
	public void redirectForAuthentication(HttpServletRequest request, HttpServletResponse response) throws IOException
	{
		authHelper.sendAuthRedirect(request, response, null, authHelper.getRedirectURIs());
	}

	@Override
	public boolean isAccessTokenExpired(HttpServletRequest request, HttpServletResponse response)
	{
		IAuthenticationResult result = SessionManagementHelper.getAuthSessionObject(request);
		return result.expiresOnDate().before(new Date());
	}

	@Override
	public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws Throwable
	{
		IAuthenticationResult authResult = authHelper.getAuthResultBySilentFlow(request, response);
		SessionManagementHelper.setSessionPrincipal(request, authResult);
	}

	@Override
	public void removePrincipleFromSession(HttpServletRequest httpRequest)
	{
		SessionManagementHelper.removePrincipalFromSession(httpRequest);
	}

	@Override
	public String getUserName(Object result) throws ParseException
	{
		boolean email_login = MSysConfig.getBooleanValue(MSysConfig.USE_EMAIL_FOR_LOGIN, false);
		JWTClaimsSet jwtClaimsSet = JWTParser.parse(((IAuthenticationResult) result).idToken()).getJWTClaimsSet();
		if (email_login)
			return (String) jwtClaimsSet.getClaim("email");
		else
			return (String) jwtClaimsSet.getClaim("name");

	}

	@Override
	public Language getLanguage(Object result) throws ParseException
	{
		return Language.getBaseLanguage();
	}
}
