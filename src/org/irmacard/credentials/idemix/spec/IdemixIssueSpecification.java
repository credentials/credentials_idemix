/**
 * IdemixIssueSpecification.java
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
 * Copyright (C) Pim Vullers, Radboud University Nijmegen, May 2012,
 * Copyright (C) Wouter Lueks, Radboud Univeristy Nijmegen, August 2012.
 */

package org.irmacard.credentials.idemix.spec;

import java.math.BigInteger;
import java.net.URI;
import java.util.Iterator;

import org.irmacard.credentials.Attributes;
import org.irmacard.credentials.spec.IssueSpecification;

import com.ibm.zurich.idmx.dm.Values;
import com.ibm.zurich.idmx.issuance.IssuanceSpec;
import com.ibm.zurich.idmx.key.IssuerKeyPair;


/**
 * Idemix flavoured IssueSpecification
 * 
 * This class implements the conversion from the generic specification to the 
 * Idemix specific one which can be used as input for the terminal and library. 
 */
public class IdemixIssueSpecification extends IssueSpecification {
	private IssuanceSpec issueSpec;
	private short credId;

	public IdemixIssueSpecification(IssuanceSpec issueSpec, short credId) {
		this.issueSpec = issueSpec;
		this.credId = credId;
	}

	/**
	 * Create an IdemixIssueSpecification based on an Idemix Issuance
	 * Specification XML file.
	 *
	 * Note: for now we assume that the system parameters, group parameters
	 * and issuer public key have already been loaded if you use this version.
	 */
	public static IdemixIssueSpecification fromIdemixIssuanceSpec(
			URI ipkID, URI credStructID, short credId) {
		IssuanceSpec issueSpec = new IssuanceSpec(ipkID, credStructID);

		return new IdemixIssueSpecification(issueSpec, credId);
	}

	/**
	 * Get the IssuerKeyPair that should be used to issue the credential.
	 *   
	 * @return the issuer key pair.
	 */
	public IssuerKeyPair getIssuerKey() {
		// TODO: implement generation/discovery of Idemix IssuerKeyPair.
		
		return new IssuerKeyPair(null);
	}
		
	/**
	 * Get an Idemix flavoured issuance specification that should be used to 
	 * issue the credential.
	 * 
	 * @return the issuance specification.
	 */
	public IssuanceSpec getIssuanceSpec() {
		return issueSpec;
	}
	
	/**
	 * Get an Idemix flavoured list of the attribute values to issued.
	 * 
	 * @param attributes to be issued.
	 * @return the attribute values.
	 */
	public Values getValues(Attributes attributes) {
		Values values = new Values(
				getIssuanceSpec().getPublicKey().getGroupParams().getSystemParams());
		
		Iterator<String> i = attributes.getIdentifiers().iterator();
		while (i.hasNext()) {
			String id = i.next();
			values.add(id, new BigInteger(1, attributes.get(id)));
		}
		
		return values;
	}

	/**
	 * Returns the short identifier used by the card to locate and identify the
	 * credential.
	 */
	public short getIdemixId() {
		return credId;
	}
}
