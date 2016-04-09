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

import org.irmacard.credentials.idemix.IdemixPublicKey;
import org.irmacard.credentials.idemix.IdemixSecretKey;
import org.irmacard.credentials.info.BasicFileReader;
import org.irmacard.credentials.info.FileReader;
import org.irmacard.credentials.info.InfoException;
import org.irmacard.credentials.info.IssuerIdentifier;

import java.net.URI;
import java.util.ArrayList;

@SuppressWarnings("unused")
public class IdemixKeyStoreDeserializer {
	private FileReader fileReader;

	public IdemixKeyStoreDeserializer(URI coreLocation) {
		fileReader = new BasicFileReader(coreLocation);
	}

	public IdemixKeyStoreDeserializer(FileReader reader) {
		this.fileReader = reader;
	}

	public String getPublicKeyPath(IssuerIdentifier issuer, int counter) {
		return String.format(issuer.getPath(false) + "/" + IdemixKeyStore.PUBLIC_KEY_FILE, counter);
	}

	public String getPrivateKeyPath(IssuerIdentifier issuer, int counter) {
		return String.format(issuer.getPath(false) + "/" + IdemixKeyStore.PRIVATE_KEY_FILE, counter);
	}

	public ArrayList<Integer> getPublicKeyCounters(IssuerIdentifier issuer) throws InfoException {
		String[] files = fileReader.list(issuer.getPath(false) + "/PublicKeys");
		if (files == null || files.length == 0)
			throw new InfoException("No keys found for issuer " + issuer);

		ArrayList<Integer> counters = new ArrayList<>(files.length);
		for (String filename : files) {
			if (filename.startsWith("."))
				continue;
			counters.add(Integer.valueOf(filename.substring(0, filename.length() - 4)));
		}

		return counters;
	}

	public IdemixPublicKey loadPublicKey(IssuerIdentifier issuer, int counter) throws InfoException {
		return new IdemixPublicKey(fileReader.retrieveFile(getPublicKeyPath(issuer, counter)));
	}

	public IdemixSecretKey loadPrivateKey(IssuerIdentifier issuer, int counter) throws InfoException {
		return new IdemixSecretKey(fileReader.retrieveFile(getPrivateKeyPath(issuer, counter)));
	}
}
