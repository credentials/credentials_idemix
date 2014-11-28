/**
 * IdemixCredential.java
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
 * Copyright (C) Wouter Lueks, Radboud University Nijmegen, November 2014.
 */

package org.irmacard.credentials.idemix;

import java.math.BigInteger;
import java.util.List;

/**
 * Represents and Idemix credential.
 *
 */
public class IdemixCredential {
	private CLSignature signatue;
	private IdemixPublicKey issuer_pk;
	private BigInteger secret;
	private List<BigInteger> attributes;

	public IdemixCredential(IdemixPublicKey issuer_pk, BigInteger secret, List<BigInteger> attributes, CLSignature signature) {
		this.issuer_pk = issuer_pk;
		this.secret = secret;
		this.attributes = attributes;
		this.signatue = signature;
	}
}
