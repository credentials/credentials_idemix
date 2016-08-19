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

package org.irmacard.credentials.idemix;

import org.irmacard.credentials.Attributes;
import org.irmacard.credentials.idemix.proofs.ProofBuilder;
import org.irmacard.credentials.idemix.proofs.ProofD;
import org.irmacard.credentials.idemix.proofs.ProofDBuilder;
import org.irmacard.credentials.idemix.proofs.ProofListBuilder;
import org.irmacard.credentials.idemix.util.Crypto;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Vector;

/**
 * Represents an Idemix credential.
 */
public class IdemixCredential {
	private CLSignature signature;
	private IdemixPublicKey issuer_pk;
	private List<BigInteger> attributes;

	private transient int hashCode = 0;

	public IdemixCredential(IdemixPublicKey issuer_pk,
			List<BigInteger> attributes, CLSignature signature) {
		this.issuer_pk = issuer_pk;
		this.attributes = attributes;
		this.signature = signature;
	}

	public CLSignature getSignature() {
		return signature;
	}

	public IdemixPublicKey getPublicKey() {
		return issuer_pk;
	}

	public IdemixCredential(IdemixPublicKey issuer_pk, BigInteger secret,
			List<BigInteger> attributes, CLSignature signature) {
		this.issuer_pk = issuer_pk;

		// Secret is 0-th attribute
		this.attributes = new Vector<BigInteger>();
		this.attributes.add(secret);
		this.attributes.addAll(attributes);

		this.signature = signature;
	}

	/**
	 * A disclosure proof of this credential for the given set of disclosed
	 * attributes. The proof also contains the revealed values.
	 *
	 * @param disclosed_attributes
	 *            Indices of attributes that have to be disclosed (1-based)
	 * @param context
	 *            The context
	 * @param nonce1
	 *            Nonce for the non-interactive proof
	 *
	 * @return disclosure proof for the given disclosed attributes
	 */
	public ProofD createDisclosureProof(List<Integer> disclosed_attributes, BigInteger context, BigInteger nonce1) {
		ProofDBuilder builder = new ProofDBuilder(this, disclosed_attributes);
		return (ProofD) builder.createProof(context, nonce1);
	}

	public int getNrAttributes() {
		return attributes.size();
	}

	public BigInteger getAttribute(int i) {
		return attributes.get(i);
	}

	public Attributes getAllAttributes() {
		return new Attributes(attributes);
	}

	public int getKeyCounter() {
		return new Attributes(attributes.get(1)).getKeyCounter();
	}

	private List<Integer> getUndisclosedAttributes(List<Integer> disclosed_attributes) {
		List<Integer> undisclosed_attributes = new Vector<Integer>();
		for(int i = 0; i < attributes.size(); i++) {
			if(!disclosed_attributes.contains(i)) {
				undisclosed_attributes.add(i);
			}
		}
		return undisclosed_attributes;
	}

	@Override
	public int hashCode() {
		if (hashCode == 0) {
			try {
				MessageDigest hash = MessageDigest.getInstance("SHA-256");

				hash.update(signature.getA().toByteArray());
				hash.update(signature.get_e().toByteArray());
				hash.update(signature.get_v().toByteArray());

				for (BigInteger attr : attributes)
					hash.update(attr.toByteArray());

				hashCode = ByteBuffer.wrap(hash.digest()).getInt();
			} catch (NoSuchAlgorithmException e) {
				throw new RuntimeException(e);
			}
		}

		return hashCode;
	}
}
