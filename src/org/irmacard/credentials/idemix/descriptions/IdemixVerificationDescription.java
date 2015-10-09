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
import java.util.LinkedList;
import java.util.List;
import java.util.Random;

import org.irmacard.credentials.idemix.IdemixPublicKey;
import org.irmacard.credentials.idemix.util.Crypto;
import org.irmacard.credentials.info.AttributeDescription;
import org.irmacard.credentials.info.DescriptionStore;
import org.irmacard.credentials.info.InfoException;
import org.irmacard.credentials.info.VerificationDescription;

public class IdemixVerificationDescription {
	private VerificationDescription vd;
	private IdemixCredentialDescription cd;

	public IdemixVerificationDescription(VerificationDescription vd) throws InfoException {
		this.vd = vd;
		this.cd = new IdemixCredentialDescription(vd.getCredentialDescription());
	}

	public IdemixVerificationDescription(String verifier, String credential)
			throws InfoException {
		this.vd = DescriptionStore.getInstance()
				.getVerificationDescriptionByName(verifier, credential);
		this.cd = new IdemixCredentialDescription(vd.getCredentialDescription());
	}

	public List<Integer> getDisclosedAttributeIdxs() {
		List<Integer> disclosed = new LinkedList<Integer>();

		// Add placeholder for metadata attribute
		disclosed.add(1);

		// Add attributes
		List<AttributeDescription> attributes = vd.getCredentialDescription().getAttributes();
		for(int i = 0; i < attributes.size(); i ++) {
			AttributeDescription attribute = attributes.get(i);
			if(vd.isDisclosed(attribute.getName())) {
				disclosed.add(i + 2);
			}
		}

		return disclosed;
	}

	public short getDisclosureMask() {
		short mask = 0;
		List<Integer> idxs = getDisclosedAttributeIdxs();
		for(int i : idxs) {
			mask |= 1 << i;
		}

		// TODO check cast, especially when MSB of short is 1
		return mask;
	}

	public int numberOfAttributes() {
		// Fixed attributes: Master Secret and Metadata
		return cd.numberOfAttributes();
	}

	public String getAttributeName(int i) {
		return cd.getAttributeName(i);
	}

	public boolean isDisclosed(int i) {
		if(i == 0) {
			return false;
		} else if (i == 1) {
			return true;
		} else {
			return vd.isDisclosed(getAttributeName(i));
		}
	}

	public VerificationDescription getVerificationDescription() {
		return vd;
	}

	public BigInteger getContext() {
		// TODO: need better derivation of context
		return Crypto.sha256Hash(vd.toString().getBytes());
	}

	public IdemixPublicKey getIssuerPublicKey() {
		return cd.getPublicKey();
	}

	public BigInteger generateNonce() {
		Random rnd = new Random();
		return new BigInteger(cd.getPublicKey().getSystemParameters().l_statzk, rnd);
	}
}
