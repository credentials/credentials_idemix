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

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.util.HashMap;

/**
 * TODO: Change print statements to proper Logging statements
 */
public class IdemixKeyStore {
	static private URI CORE_LOCATION;
	static private TreeWalkerI treeWalker;

	static private final String PUBLIC_KEY_FILE = "ipk.xml";
	static private final String PRIVATE_KEY_FILE = "private/isk.xml";

	static IdemixKeyStore ds;

	static private IdemixKeyStoreSerializer serializer;
	static private IdemixKeyStoreDeserializerI deserializer;
	static private HttpClient httpClient;

	private HashMap<String, IdemixPublicKey> publicKeys = new HashMap<String, IdemixPublicKey>();
	private HashMap<String, IdemixSecretKey> secretKeys = new HashMap<String, IdemixSecretKey>();

	/**
	 * Define the CoreLocation. This has to be set before using the
	 * DescriptionStore or define a TreeWalker instead.
	 *
	 * @param coreLocation
	 *            Location of configuration files.
	 */
	public static void setCoreLocation(URI coreLocation) {
		// Make sure we have the correct URI, including trailing slash
		File core = new File(coreLocation);
		CORE_LOCATION = core.toURI();
	}

	/**
	 * Define the TreeWalker. This allows crawling more difficult storage
	 * systems, like Android's. This has to be set before using the
	 * DescriptionStore or define a coreLocation instead.
	 *
	 * @param treeWalker
	 */
	public static void setTreeWalker(TreeWalkerI treeWalker) {
		IdemixKeyStore.treeWalker = treeWalker;
	}

	public static void setDeserializer(IdemixKeyStoreDeserializerI deserializer) {
		IdemixKeyStore.deserializer = deserializer;
	}

	public static void setSerializer(IdemixKeyStoreSerializer serializer) {
		IdemixKeyStore.serializer = serializer;
	}

	public static void setHttpClient(HttpClient client) {
		IdemixKeyStore.httpClient = client;
	}

	/**
	 * Get DescriptionStore instance
	 *
	 * @return The IdemixKeyStore instance
	 * @throws InfoException if instantiating the IdemixKeyStore failed
	 */
	public static IdemixKeyStore getInstance() throws InfoException {
		if (ds == null) {
			if (CORE_LOCATION != null) {
				treeWalker = new TreeWalker(CORE_LOCATION);
			}

			if (treeWalker != null && deserializer == null) {
				deserializer = new IdemixKeyStoreDeserializer(CORE_LOCATION, treeWalker);
			}

			if (deserializer != null) {
				ds = deserializer.deserializeIdemixKeyStore();
			}
		}

		return ds;
	}

	public static void setInstance(IdemixKeyStore instance) {
		ds = instance;
	}

	public static boolean isLocationSet() {
		return CORE_LOCATION != null;
	}

	public void updatePublicKey(IssuerDescription id, IdemixPublicKey ipk) {
		if (publicKeys.containsKey(id.getID())) {
			publicKeys.remove(id.getID());
		}
		publicKeys.put(id.getID(), ipk);
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

		IssuerDescription issuer = DescriptionStore.getInstance().downloadIssuerDescription(name, false);

		String url = manager.getUrl() + name + "/ipk.xml";
		InputStream stream = DescriptionStore.doHttpRequest(url);

		ds.updatePublicKey(issuer, new IdemixPublicKey(stream));

		save();
		return issuer;
	}

	protected void save() {
		if (serializer != null)
			serializer.saveIdemixKeyStore(this);
	}
}
