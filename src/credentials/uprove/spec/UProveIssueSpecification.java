/**
 * UProveIssueSpecification.java
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
 * Copyright (C) Pim Vullers, Radboud University Nijmegen, May 2012.
 */

package credentials.uprove.spec;

import java.util.Iterator;

import com.microsoft.uprove.IssuerProtocolParameters;
import com.microsoft.uprove.ProverProtocolParameters;

import credentials.Attributes;
import credentials.spec.IssueSpecification;

/**
 * U-Prove flavoured IssueSpecification
 * 
 * This class implements the conversion from the generic specification to the 
 * U-Prove specific one which can be used as input for the terminal and library. 
 */
public class UProveIssueSpecification extends IssueSpecification {

	public IssuerProtocolParameters getIssuerProtocolParameters() {		
        return new IssuerProtocolParameters();
	}

	public ProverProtocolParameters getProverProtocolParameters() {
		return new ProverProtocolParameters();
	}
	
	public int[] getDisclosedAttributes() {
		return null;
	}
	
	public byte[][] getValues(Attributes attributes) {
		byte[][] values = new byte[attributes.getIdentifiers().size()][];
		
		// TODO: Fix attribute order
		Iterator<String> i = attributes.getIdentifiers().iterator();
		int j = 0;
		while (i.hasNext()) {
			String id = i.next();
			values[j++] = attributes.get(id);
		}
		
		return values;
	}
}
