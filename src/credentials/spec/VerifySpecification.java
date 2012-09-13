/**
 * VerifySpecification.java
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
 * Copyright (C) Wouter Lueks, Radboud University Nijmegen, August 2012.
 */

package credentials.spec;

import java.util.Vector;

/**
 * Generic VerifySpecification
 * 
 * This class implements the generic setters which can be used by application 
 * developers as input to the credentials system. 
 */
public class VerifySpecification extends Specification {
	
	/**
	 * The credential that needs to be verified.
	 *
	 * TODO: WL: why is this a string? Might need to be something a bit more general.
	 */
	protected String credential;
	
	/**
	 * The attributes that need to be disclosed.
	 */
	protected Vector<String> attributes;

	public void setCredentialIdentifier(String id) {
		credential = id;
	}
	
	public String getCredentialIdentifier() {
		return credential;
	}
	
	public void setAttributeIdentifiers(Vector<String> ids) {
		attributes = ids;
	}
	
	public void addAttributeIdentifier(String id) {
		attributes.add(id);
	}
	
	public Vector<String> getAttributeIdentifiers() {
		return attributes;
	}
}
