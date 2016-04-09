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
import java.util.Arrays;
import java.util.HashMap;

@SuppressWarnings("unused")
public class IdemixKeyStore extends KeyStore {
	static public final String PUBLIC_KEY_FILE = "PublicKeys/%d.xml";
	static public final String PRIVATE_KEY_FILE = "PrivateKeys/%d.xml";

	static private IdemixKeyStore ds;

	static private IdemixKeyStoreSerializer serializer;
	static private IdemixKeyStoreDeserializer deserializer;
	static private HttpClient httpClient;

	private HashMap<IssuerIdentifier, HashMap<Integer,IdemixPublicKey>> publicKeys = new HashMap<>();
	private HashMap<IssuerIdentifier, HashMap<Integer,IdemixSecretKey>> secretKeys = new HashMap<>();

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

		KeyStore.setInstance(ds);
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

	public void setPublicKey(IssuerIdentifier issuer, IdemixPublicKey ipk, int counter) {
		if (!publicKeys.containsKey(issuer))
			publicKeys.put(issuer, new HashMap<Integer, IdemixPublicKey>(1));

		publicKeys.get(issuer).put(counter, ipk);
	}

	public boolean containsPublicKey(IssuerIdentifier issuer, int counter) {
		if (!publicKeys.containsKey(issuer))
			return false;
		return publicKeys.get(issuer).containsKey(counter);
	}

	@Override
	public IdemixPublicKey getPublicKey(IssuerIdentifier issuer, int counter) throws InfoException {
		if (publicKeys.containsKey(issuer) && publicKeys.get(issuer).containsKey(counter))
			return publicKeys.get(issuer).get(counter);

		throw new InfoException("Public key " + counter + " for issuer " + issuer + " not found");
	}

	public IdemixPublicKey getLatestPublicKey(IssuerIdentifier issuer) throws InfoException {
		return getPublicKey(issuer, getKeyCounter(issuer));
	}

	public boolean containsSecretKey(IssuerIdentifier issuer, int counter) {
		if (!secretKeys.containsKey(issuer))
			return false;
		return secretKeys.get(issuer).containsKey(counter);
	}

	public IdemixSecretKey getSecretKey(IssuerIdentifier issuer, int counter) throws InfoException {
		if (secretKeys.containsKey(issuer) && secretKeys.get(issuer).containsKey(counter))
			return secretKeys.get(issuer).get(counter);

		throw new InfoException("Secret key " + counter + " for issuer " + issuer + " not found");
	}

	public IdemixSecretKey getLatestSecretKey(IssuerIdentifier issuer) throws InfoException {
		return getSecretKey(issuer, getKeyCounter(issuer));
	}

	public void setSecretKey(IssuerIdentifier issuer, IdemixSecretKey sk, int counter) {
		if (!secretKeys.containsKey(issuer))
			secretKeys.put(issuer, new HashMap<Integer, IdemixSecretKey>(1));

		secretKeys.get(issuer).put(counter, sk);
	}

	/**
	 * Get the highest counter of all public keys that are stored for the specified issuer.
	 * @throws InfoException if no public keys for the specified issuer are present
	 */
	public int getKeyCounter(IssuerIdentifier issuer) throws InfoException {
		if (publicKeys.get(issuer) == null)
			throw new InfoException("No public keys for issuer " + issuer);

		// Put all counters in an array, sort it, and return the biggest element
		Integer[] counters = new Integer[publicKeys.get(issuer).size()];
		publicKeys.get(issuer).keySet().toArray(counters);
		Arrays.sort(counters);
		return counters[counters.length - 1];
	}

	/**
	 * Download a public key from the scheme manager.
	 * @param issuer The issuer to whom the key belongs
	 * @param counter The public key counter
	 * @return The key
	 * @throws IOException if the file could not be downloaded
	 * @throws InfoException if the scheme manager was unknown
	 */
	public IdemixPublicKey downloadPublicKey(IssuerIdentifier issuer, int counter) throws IOException, InfoException {
		IssuerDescription id = DescriptionStore.getInstance().getIssuerDescription(issuer);
		SchemeManager manager = DescriptionStore.getInstance().getSchemeManager(issuer.getSchemeManagerName());
		if (manager == null)
			throw new InfoException("Unknown scheme manager");

		String url = manager.getUrl() + issuer.getPath(false) + "/";

		String pkXml = DescriptionStore.inputStreamToString(
				DescriptionStore.doHttpRequest(url + String.format(PUBLIC_KEY_FILE, counter)));
		IdemixPublicKey pk = new IdemixPublicKey(pkXml);

		setPublicKey(issuer, pk, counter);
		if (serializer != null)
			serializer.saveIdemixKey(id, pkXml, counter);
		return pk;
	}
}
