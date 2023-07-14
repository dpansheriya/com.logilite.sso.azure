// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package com.logilite.sso.azure.principal;

import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.adempiere.base.sso.ISSOPrincipalService;
import org.compiere.util.Util;

import com.microsoft.aad.msal4j.IAuthenticationResult;

/**
 * Helpers for managing session
 */
public class SessionManagementHelper
{

	public static final String	STATE							= "state";
	public static final String	STATES							= "states";
	public static final Integer	STATE_TTL						= 3600;

	public static final String	FAILED_TO_VALIDATE_MESSAGE		= "Failed to validate data received from Authorization service - ";
	public static final String	TOKEN_CACHE_SESSION_ATTRIBUTE	= "sso.token.cache";

	static StateData validateState(HttpSession session, String state) throws Exception
	{
		if (!Util.isEmpty(state))
		{
			StateData stateDataInSession = removeStateFromSession(session, state);
			if (stateDataInSession != null)
			{
				return stateDataInSession;
			}
		}
		throw new Exception(FAILED_TO_VALIDATE_MESSAGE + "could not validate state");
	}

	private static StateData removeStateFromSession(HttpSession session, String state)
	{
		@SuppressWarnings("unchecked")
		Map<String, StateData> states = (Map<String, StateData>) session.getAttribute(STATES);
		if (states != null)
		{
			eliminateExpiredStates(states);
			StateData stateData = states.get(state);
			if (stateData != null)
			{
				states.remove(state);
				return stateData;
			}
		}
		return null;
	}

	private static void eliminateExpiredStates(Map<String, StateData> map)
	{
		Iterator<Map.Entry<String, StateData>> it = map.entrySet().iterator();

		Date currTime = new Date();
		while (it.hasNext())
		{
			Map.Entry<String, StateData> entry = it.next();
			long diffInSeconds = TimeUnit.MILLISECONDS.toSeconds(currTime.getTime() - entry.getValue().getExpirationDate().getTime());

			if (diffInSeconds > STATE_TTL)
			{
				it.remove();
			}
		}
	}

	@SuppressWarnings("unchecked")
	static void storeStateAndNonceInSession(HttpSession session, String state, String nonce)
	{

		// state parameter to validate response from Authorization server and nonce parameter to
		// validate idToken
		if (session.getAttribute(STATES) == null)
		{
			session.setAttribute(STATES, new HashMap<String, StateData>());
		}
		((Map<String, StateData>) session.getAttribute(STATES)).put(state, new StateData(nonce, new Date()));
	}

	static void storeTokenCacheInSession(HttpServletRequest httpServletRequest, String tokenCache)
	{
		httpServletRequest.getSession().setAttribute(TOKEN_CACHE_SESSION_ATTRIBUTE, tokenCache);
	}

	public static void setSessionPrincipal(HttpServletRequest httpRequest, IAuthenticationResult result)
	{
		httpRequest.getSession().setAttribute(ISSOPrincipalService.SSO_PRINCIPAL_SESSION_TOKEN, result);
	}

	public static void removePrincipalFromSession(HttpServletRequest httpRequest)
	{
		httpRequest.getSession().removeAttribute(ISSOPrincipalService.SSO_PRINCIPAL_SESSION_TOKEN);
	}

	public static IAuthenticationResult getAuthSessionObject(HttpServletRequest request)
	{
		Object token = request.getSession().getAttribute(ISSOPrincipalService.SSO_PRINCIPAL_SESSION_TOKEN);
		if (token instanceof IAuthenticationResult)
		{
			return (IAuthenticationResult) token;
		}
		else
		{
			return null;
		}
	}
}
