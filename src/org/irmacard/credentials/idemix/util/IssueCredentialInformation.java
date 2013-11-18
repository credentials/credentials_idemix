/**
 * IssuerCredentialInformation.java
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
 * Copyright (C) Wouter Lueks, Radboud University Nijmegen, September 2012.
 */

package org.irmacard.credentials.idemix.util;

import java.net.URI;

import org.irmacard.credentials.Attributes;
import org.irmacard.credentials.idemix.IdemixPrivateKey;
import org.irmacard.credentials.info.DescriptionStore;
import org.irmacard.credentials.info.InfoException;

import com.ibm.zurich.idmx.issuance.Issuer;
import com.ibm.zurich.idmx.key.IssuerKeyPair;

public class IssueCredentialInformation extends CredentialInformation {
	URI issuerSKLocation;
	
	public IssueCredentialInformation(String issuer, String credName)
			throws InfoException {
		super(DescriptionStore.getInstance()
				.getCredentialDescriptionByName(issuer, credName));

		issuerSKLocation = baseLocation.resolve("private/isk.xml");

		setupIssuer();
	}
	
	public IdemixPrivateKey getIdemixPrivateKey() {
		IssuerKeyPair ikp;
		try {
			ikp = (IssuerKeyPair) init(issuerSKLocation, issuerSKLocation);
		} catch (InfoException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			throw new RuntimeException(e);
		}
		return new IdemixPrivateKey(ikp.getPrivateKey());
	}
	
    public void setupIssuer() {
    	getIdemixPrivateKey();
    }
    
    public Issuer getIssuer(Attributes attributes) {
		return new Issuer(getIdemixPrivateKey().getIssuerKeyPair(),
				getIdemixIssueSpecification().getIssuanceSpec(), null, null,
				getIdemixIssueSpecification().getValues(attributes));
	}
}
