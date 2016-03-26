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

package org.irmacard.credentials.idemix.descriptions;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.irmacard.credentials.idemix.IdemixPublicKey;
import org.irmacard.credentials.idemix.info.IdemixKeyStore;
import org.irmacard.credentials.idemix.util.Crypto;
import org.irmacard.credentials.info.CredentialDescription;
import org.irmacard.credentials.info.DescriptionStore;
import org.irmacard.credentials.info.InfoException;

public class IdemixCredentialDescription {
	private CredentialDescription cd;
	private IdemixPublicKey pk;

	public IdemixCredentialDescription(CredentialDescription cd) throws InfoException {
		this.cd = cd;
		setupPK();
	}

	private void setupPK() throws InfoException {
		this.pk = IdemixKeyStore.getInstance().getPublicKey(cd.getIssuerDescription());
	}

	public int numberOfAttributes() {
		// Fixed attribute: Metadata
		return cd.getAttributes().size() + 1;
	}

	public IdemixPublicKey getPublicKey() {
		return pk;
	}

	public BigInteger getContext() {
		// TODO: need better derivation of context
		return Crypto.sha256Hash(cd.toString().getBytes());
	}

	public CredentialDescription getCredentialDescription() {
		return cd;
	}

	public String getAttributeName(int i) {
		if(i == 0) {
			return "master";
		} else if (i == 1) {
			return "metadata";
		} else {
			return cd.getAttributeNames().get(i - 2);
		}
	}

	public BigInteger generateNonce() throws InfoException {
		SecureRandom rnd = new SecureRandom();
		return new BigInteger(pk.getSystemParameters().l_statzk, rnd);
	}
}
