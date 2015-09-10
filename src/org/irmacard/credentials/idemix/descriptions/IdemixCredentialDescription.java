/**
 * IdemixVerificationDescription.java
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
 * Copyright (C) Wouter Lueks, Radboud University Nijmegen, January 2015.
 */

package org.irmacard.credentials.idemix.descriptions;

import java.math.BigInteger;
import java.util.Random;

import org.irmacard.credentials.idemix.IdemixPublicKey;
import org.irmacard.credentials.idemix.info.IdemixKeyStore;
import org.irmacard.credentials.idemix.util.Crypto;
import org.irmacard.credentials.info.CredentialDescription;
import org.irmacard.credentials.info.DescriptionStore;
import org.irmacard.credentials.info.InfoException;

public class IdemixCredentialDescription {
	private CredentialDescription cd;
	private IdemixPublicKey pk;

	public IdemixCredentialDescription(String issuer, String cred) throws InfoException {
		this.cd = DescriptionStore.getInstance().getCredentialDescriptionByName(issuer, cred);
		setupPK();
	}

	public IdemixCredentialDescription(CredentialDescription cd) throws InfoException {
		this.cd = cd;
		setupPK();
	}

	private void setupPK() throws InfoException {
		this.pk = IdemixKeyStore.getInstance().getPublicKey(cd.getIssuerID());
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
		Random rnd = new Random();
		return new BigInteger(pk.getSystemParameters().l_statzk, rnd);
	}
}
