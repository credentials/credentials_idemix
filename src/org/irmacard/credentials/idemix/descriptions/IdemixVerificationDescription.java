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
import java.util.LinkedList;
import java.util.List;
import java.security.SecureRandom;

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
		SecureRandom rnd = new SecureRandom();
		return new BigInteger(cd.getPublicKey().getSystemParameters().l_statzk, rnd);
	}
}
