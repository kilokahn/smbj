/*
 * Copyright (C)2016 - SMBJ Contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.hierynomus.smbj.auth;

import java.io.IOException;
import java.util.Random;

import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.hierynomus.protocol.commons.ByteArrayUtils;
import com.hierynomus.protocol.transport.TransportException;
import com.hierynomus.security.SecurityProvider;
import com.hierynomus.smbj.session.Session;

public class PlatformGSSAuthenticator implements Authenticator {

    private static final String MECH_KERBEROS_OID = "1.2.840.113554.1.2.2";
    private static final Logger logger = LoggerFactory.getLogger(PlatformGSSAuthenticator.class);

    public static class Factory implements com.hierynomus.protocol.commons.Factory.Named<Authenticator> {

        @Override
        public String getName() {
            return MECH_KERBEROS_OID;
        }

        @Override
        public PlatformGSSAuthenticator create() {
            return new PlatformGSSAuthenticator();
        }
    }

    private GSSContext gssContext;

    @Override
    public void init(SecurityProvider securityProvider, Random random) {
        // No-op
    }

    @Override
    public boolean supports(AuthenticationContext context) {
        return context.getClass().equals(PlatformGSSAuthenticationContext.class);
    }

    @Override
    public AuthenticateResponse authenticate(AuthenticationContext context, byte[] gssToken, Session session)
        throws IOException {
        return authenticateSession(context, gssToken, session);
    }

    private AuthenticateResponse authenticateSession(AuthenticationContext context, byte[] gssToken, Session session)
        throws TransportException {
        try {
            logger.debug("Authenticating on {} using GSSAPI", session.getConnection().getRemoteHostname());
            if (gssContext == null) {
                GSSManager gssManager = GSSManager.getInstance();
                Oid oid = new Oid(MECH_KERBEROS_OID);

                String service = "cifs";
                String hostName = session.getConnection().getRemoteHostname();
                GSSName serverName = gssManager.createName(service + "@" + hostName, GSSName.NT_HOSTBASED_SERVICE);
                gssContext = gssManager.createContext(serverName, oid, null, GSSContext.DEFAULT_LIFETIME);
                gssContext.requestMutualAuth(true);
                // TODO fill in all the other options too
            }

            byte[] newToken = gssContext.initSecContext(gssToken, 0, gssToken.length);

            if (newToken != null) {
                logger.trace("Received token: {}", ByteArrayUtils.printHex(newToken));
            }

            AuthenticateResponse response = new AuthenticateResponse(newToken);
            return response;
        } catch (GSSException e) {
            throw new TransportException(e);
        }

    }
}
