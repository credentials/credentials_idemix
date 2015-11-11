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

import java.io.File;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashMap;

import org.irmacard.credentials.idemix.IdemixPublicKey;
import org.irmacard.credentials.idemix.IdemixSecretKey;
import org.irmacard.credentials.info.CredentialDescription;
import org.irmacard.credentials.info.DescriptionStore;
import org.irmacard.credentials.info.InfoException;
import org.irmacard.credentials.info.IssuerDescription;
import org.irmacard.credentials.info.TreeWalker;
import org.irmacard.credentials.info.TreeWalkerI;

/**
 * TODO: Change print statements to proper Logging statements
 */
public class IdemixKeyStore {
	static private URI CORE_LOCATION;
	static private TreeWalkerI treeWalker;

	static private final String PUBLIC_KEY_FILE = "ipk.xml";
	static private final String PRIVATE_KEY_FILE = "private/isk.xml";

	static IdemixKeyStore ds;

	HashMap<IssuerDescription, IdemixPublicKey> publicKeys =
			new HashMap<IssuerDescription, IdemixPublicKey>();

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

	/**
	 * Get DescriptionStore instance
	 *
	 * @return The IdemixKeyStore instance
	 * @throws Exception
	 *             if CoreLocation has not been set
	 */
	public static IdemixKeyStore getInstance() throws InfoException {
		if (ds == null) {
			ds = new IdemixKeyStore();
		}

		return ds;
	}

	private IdemixKeyStore() throws InfoException {
		if (CORE_LOCATION != null) {
			treeWalker = new TreeWalker(CORE_LOCATION);
		}

		if (treeWalker != null) {
			retrieveIdemixKeys();
		}
	}

	private void retrieveIdemixKeys() throws InfoException {
		DescriptionStore ds = DescriptionStore.getInstance();

		for (IssuerDescription id : ds.getIssuerDescriptions()) {
			URI path;
			try {
				path = new URI(id.getID() + "/").resolve(PUBLIC_KEY_FILE);
			} catch (URISyntaxException e) {
				e.printStackTrace();
				throw new RuntimeException();
			}

			try {
				/*
				 * TODO: this is a bit of cludge, better refactor
				 * IssuerDescription into EntityDescription which is subclassed
				 * by IssuerDescription and Verifier Description, or something
				 * like that.
				 */
				IdemixPublicKey ipk = new IdemixPublicKey(
						treeWalker.retrieveFile(path));
				publicKeys.put(id, ipk);
			} catch (InfoException e) {
				// Ignoring Entity when no key is found
			}
		}
	}

	public void updatePublicKey(IssuerDescription id, IdemixPublicKey ipk) {
		if (publicKeys.containsKey(id)) {
			publicKeys.remove(id);
		}
		publicKeys.put(id, ipk);
	}

	public IdemixPublicKey getPublicKey(String issuer) throws InfoException {
		IssuerDescription id = DescriptionStore.getInstance()
				.getIssuerDescription(issuer);

		if (publicKeys.containsKey(id)) {
			return publicKeys.get(id);
		} else {
			throw new InfoException("Public key for issuer " + issuer
					+ " not found.");
		}
	}

	public IdemixSecretKey getSecretKey(CredentialDescription cd) throws InfoException {
		return getSecretKey(cd.getIssuerDescription());
	}

	public IdemixSecretKey getSecretKey(IssuerDescription id) throws InfoException {
		URI path;
		try {
			path = new URI(id.getID() + "/").resolve(PRIVATE_KEY_FILE);
		} catch (URISyntaxException e) {
			throw new RuntimeException(e);
		}
		return new IdemixSecretKey(treeWalker.retrieveFile(path));
	}

	public IdemixPublicKey getPublicKey(IssuerDescription id) {
		return publicKeys.get(id);
	}
}
