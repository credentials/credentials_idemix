/**
 * VerifyCredentialStructureCreator.java
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

public class IdemixCredentialStructureCreator {
	final static String HEADER = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
			+ "<CredentialStructure xmlns=\"http://www.zurich.ibm.com/security/idemix\"\n"
			+ "\t    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"\n"
			+ "\t    xmlns:xs=\"http://www.w3.org/2001/XMLSchema\"\n"
			+ "\t    xsi:schemaLocation=\"http://www.zurich.ibm.com/security/idemix CredentialStructure.xsd\">\n"
			+ "\t<Attributes>\n";

	final static String MIDDLE = "\t</Attributes>\n" + "\t<Features/>\n"
			+ "\t<Implementation>\n" + "\t\t<AttributeOrder>\n";

	final static String FOOTER = "\t\t</AttributeOrder>\n" + "\t</Implementation>\n"
			+ "</CredentialStructure>\n";

	public static InputStream createCredentialStructure(CredentialDescription cd) {
		StringBuilder ret = new StringBuilder();
		ret.append(HEADER);

		// Add attributes
		List<AttributeDescription> attrs = cd.getAttributes();
		ret.append(getAttribute("metadata"));
		for(AttributeDescription attr : attrs) {
			ret.append(getAttribute(attr.getName()));
		}

		ret.append(MIDDLE);

		// Add attribute order
		ret.append(getAttributeForOrder("metadata", 1));
		for(int i = 0; i < attrs.size(); i ++) {
			ret.append(getAttributeForOrder(attrs.get(i).getName(), i + 2));
		}

		ret.append(FOOTER);
		return new ByteArrayInputStream(ret.toString().getBytes());
	}

	private static String getAttribute(String name) {
		return "\t\t<Attribute issuanceMode=\"known\" name=\"" + name + "\" type=\"int\" />\n";
	}

	private static String getAttributeForOrder(String name, int pos) {
		return "\t\t\t<Attribute name=\"" + name + "\">" + pos + "</Attribute>\n";
	}
}
