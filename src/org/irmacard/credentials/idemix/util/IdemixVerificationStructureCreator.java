/**
 * VerifyVerificationStructureCreator.java
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
 * Copyright (C) Wouter Lueks, Radboud University Nijmegen, November 2013.
 */

package org.irmacard.credentials.idemix.util;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.util.List;

import org.irmacard.credentials.info.AttributeDescription;
import org.irmacard.credentials.info.CredentialDescription;
import org.irmacard.credentials.info.DescriptionStore;
import org.irmacard.credentials.info.VerificationDescription;

public class IdemixVerificationStructureCreator {
	final static String HEADER = 
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
			"<ProofSpecification xmlns=\"http://www.zurich.ibm.com/security/idemix\"\n" +
			"\txmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"\n" +
            "\txsi:schemaLocation=\"http://www.zurich.ibm.com/security/idemix ProofSpecification.xsd\">\n" +
			"\n" +
			"\t<Declaration>\n";

	final static String MIDDLE = "\t</Declaration>\n"
			+ "\t<Specification>\n"
			+ "\t\t<Credentials>\n"
			+ "\t\t\t<Credential issuerPublicKey=\"ISSUERPK\"\n"
			+ "\t\t\t            credStruct=\"CREDSTRUCT\" name=\"someRandomName\">\n";

	final static String FOOTER = "\t\t\t</Credential>\n"
			+ "\t\t</Credentials>\n" + "\t\t<EnumAttributes />\n"
			+ "\t\t<Inequalities />\n" + "\t\t<Commitments />\n"
			+ "\t\t<Representations />\n" + "\t\t<Pseudonyms />\n"
			+ "\t\t<VerifiableEncryptions />\n" + "\t\t<Messages />\n"
			+ "\t</Specification>\n" + "</ProofSpecification>\n";

	public static InputStream createProofSpecification(VerificationDescription vd) {
        DescriptionStore ds;
        try
        {
            ds = DescriptionStore.getInstance();
        }
        catch(Exception ex)
        {
            return null;
        }

		StringBuilder ret = new StringBuilder(); 
		ret.append(HEADER);

		List<AttributeDescription> attrs = vd.getCredentialDescription().getAttributes();
		CredentialDescription cd = vd.getCredentialDescription();

		// Add placeholder for metadata attribute 
		ret.append(getAttributeId(1, "revealed"));

		// Add attributes
		for(int i = 0; i < attrs.size(); i ++) {
			AttributeDescription attr = attrs.get(i);
			ret.append(getAttributeId(i + 2,
					vd.isDisclosed(attr.getName()) ? "revealed" : "unrevealed"));
		}

        String baseURL = ds.getIssuerDescription(vd.getIssuerID()).getBaseURL();
        System.out.println("BASEURL: " + baseURL);

		String middle_tmp = MIDDLE.replaceFirst("ISSUERPK",
				baseURL + "ipk.xml");
		middle_tmp = middle_tmp.replaceFirst("CREDSTRUCT",
				baseURL + cd.getCredentialID()
						+ "/structure.xml");
		ret.append(middle_tmp);

		ret.append(getAttribute(1, "metadata"));
		for(int i = 0; i < attrs.size(); i ++) {
			AttributeDescription attr = attrs.get(i);
			ret.append(getAttribute(i + 2, attr.getName()));
		}

		ret.append(FOOTER);

		System.out.println(ret);
		return new ByteArrayInputStream(ret.toString().getBytes());
	}

	private static String getAttributeId(int idx, String mode) {
		return "\t\t<AttributeId name=\"id" + idx + "\" proofMode=\"" + mode
				+ "\" type=\"int\" />\n";
	}

	private static String getAttribute(int idx, String name) {
		return "\t\t\t\t<Attribute name=\"" + name + "\">id" + idx + "</Attribute>\n";
	}
}
