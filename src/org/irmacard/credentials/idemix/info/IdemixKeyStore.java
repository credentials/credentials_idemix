/*
 * Copyright (c) 2015, the IRMA Team
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *  Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 *
 *  Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 *  Neither the name of the IRMA project nor the names of its
 *   contributors may be used to endorse or promote products derived from
 *   this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package org.irmacard.credentials.idemix.info;

import org.apache.http.client.HttpClient;
import org.irmacard.credentials.idemix.IdemixPublicKey;
import org.irmacard.credentials.idemix.IdemixSecretKey;
import org.irmacard.credentials.info.*;

import java.io.IOException;
import java.util.HashMap;

@SuppressWarnings("unused")
public class IdemixKeyStore {
	static public final String PUBLIC_KEY_FILE = "ipk.xml";
	static public final String PRIVATE_KEY_FILE = "private/isk.xml";
	static public final String GROUP_PARAMS_FILE = "gp.xml";
	static public final String SYSTEM_PARAMS_FILE = "sp.xml";

	static private IdemixKeyStore ds;

	static private IdemixKeyStoreSerializer serializer;
	static private IdemixKeyStoreDeserializer deserializer;
	static private HttpClient httpClient;

	private HashMap<String, IdemixPublicKey> publicKeys = new HashMap<>();
	private HashMap<String, IdemixSecretKey> secretKeys = new HashMap<>();

	public static void setDeserializer(IdemixKeyStoreDeserializer deserializer) {
		IdemixKeyStore.deserializer = deserializer;
	}

	public static void setSerializer(IdemixKeyStoreSerializer serializer) {
		IdemixKeyStore.serializer = serializer;
	}

	public static void setHttpClient(HttpClient client) {
		IdemixKeyStore.httpClient = client;
	}

	public static void initialize(IdemixKeyStoreDeserializer deserializer,
	                              IdemixKeyStoreSerializer serializer,
	                              HttpClient client) throws InfoException {
		IdemixKeyStore.deserializer = deserializer;
		IdemixKeyStore.serializer = serializer;
		IdemixKeyStore.httpClient = client;
		initialize();
	}

	public static void initialize(IdemixKeyStoreDeserializer deserializer) throws InfoException {
		IdemixKeyStore.deserializer = deserializer;
		initialize();
	}

	public static void initialize() throws InfoException {
		ds = new IdemixKeyStore();
		if (deserializer != null)
			new KeyTreeWalker(deserializer).deserializeIdemixKeyStore(ds);
	}

	public static boolean isInitialized() {
		return ds != null;
	}

	/**
	 * Get DescriptionStore instance
	 *
	 * @return The IdemixKeyStore instance
	 * @throws InfoException if instantiating the IdemixKeyStore failed
	 */
	public static IdemixKeyStore getInstance() throws InfoException {
		if (ds == null)
			initialize();

		return ds;
	}

	public static void setInstance(IdemixKeyStore instance) {
		ds = instance;
	}

	public void updatePublicKey(IssuerDescription id, IdemixPublicKey ipk) {
		if (publicKeys.containsKey(id.getID())) {
			publicKeys.remove(id.getID());
		}
		publicKeys.put(id.getID(), ipk);
	}

	public boolean containsPublicKey(String issuer) {
		return publicKeys.containsKey(issuer);
	}

	public IdemixPublicKey getPublicKey(String issuer) throws InfoException {
		if (publicKeys.containsKey(issuer))
			return publicKeys.get(issuer);

		throw new InfoException("Public key for issuer " + issuer + " not found.");
	}

	public void setPublicKey(String issuer, IdemixPublicKey pk) {
		publicKeys.put(issuer, pk);
	}

	public IdemixSecretKey getSecretKey(CredentialDescription cd) throws InfoException {
		return getSecretKey(cd.getIssuerDescription());
	}

	public boolean containsSecretKey(IssuerDescription id) {
		return secretKeys.containsKey(id.getID());
	}

	public IdemixSecretKey getSecretKey(IssuerDescription id) throws InfoException {
		if (secretKeys.containsKey(id.getID()))
			return secretKeys.get(id.getID());

		throw new InfoException("Secret key for issuer " + id.getID() + " not found");
	}

	public void setSecretKey(String issuer, IdemixSecretKey sk) {
		secretKeys.put(issuer, sk);
	}

	public IdemixPublicKey getPublicKey(IssuerDescription id) {
		return publicKeys.get(id.getID());
	}

	public IssuerDescription downloadIssuer(String name) throws IOException, InfoException {
		SchemeManager manager = DescriptionStore.getInstance().getSchemeManager("default");
		if (manager == null)
			throw new InfoException("Unknown scheme manager");

		IssuerDescription issuer = DescriptionStore.getInstance().getIssuerDescription(name);
		if (issuer == null)
			issuer = DescriptionStore.getInstance().downloadIssuerDescription(name);

		String url = manager.getUrl() + name + "/";

		String pkXml = DescriptionStore.inputStreamToString(DescriptionStore.doHttpRequest(url + PUBLIC_KEY_FILE));
		String gpXml = DescriptionStore.inputStreamToString(DescriptionStore.doHttpRequest(url + GROUP_PARAMS_FILE));
		String spXml = DescriptionStore.inputStreamToString(DescriptionStore.doHttpRequest(url + SYSTEM_PARAMS_FILE));

		IdemixPublicKey pk = new IdemixPublicKey(pkXml);

		updatePublicKey(issuer, pk);
		if (serializer != null)
			serializer.saveIdemixKey(issuer, pkXml, gpXml, spXml);

		return issuer;
	}
}
