/**
 * IdemixKeyStore.java
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * Copyright (C) Wouter Lueks, Radboud University Nijmegen, December 2014.
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
