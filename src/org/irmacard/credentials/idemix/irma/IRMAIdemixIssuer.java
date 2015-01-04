/**
 * IRMAIdemixIssuer.java
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

package org.irmacard.credentials.idemix.irma;

import java.math.BigInteger;
import java.util.LinkedList;
import java.util.List;

import org.irmacard.credentials.Attributes;
import org.irmacard.credentials.CredentialsException;
import org.irmacard.credentials.idemix.IdemixIssuer;
import org.irmacard.credentials.idemix.IdemixPublicKey;
import org.irmacard.credentials.idemix.IdemixSecretKey;
import org.irmacard.credentials.idemix.descriptions.IdemixCredentialDescription;
import org.irmacard.credentials.idemix.messages.IssueCommitmentMessage;
import org.irmacard.credentials.idemix.messages.IssueSignatureMessage;

public class IRMAIdemixIssuer extends IdemixIssuer {

	public IRMAIdemixIssuer(IdemixPublicKey pk, IdemixSecretKey sk,
			BigInteger context) {
		super(pk, sk, context);
	}

	public IssueSignatureMessage issueSignature(IssueCommitmentMessage msg,
			IdemixCredentialDescription cd, Attributes attributes, BigInteger nonce1)
			throws CredentialsException {
		List<BigInteger> rawAttributes = new LinkedList<BigInteger>();
		for(int i = 1; i <= cd.numberOfAttributes(); i++) {
			rawAttributes.add(new BigInteger(1, attributes.get(cd.getAttributeName(i))));
		}
		return issueSignature(msg, rawAttributes, nonce1);
	}
}
