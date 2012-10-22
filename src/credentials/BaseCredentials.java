/**
 * BaseCredentials.java
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
 * Copyright (C) Wouter Lueks, Radboud University Nijmegen, July 2012.
 */

package credentials;

import java.util.List;
import java.util.Vector;

import net.sourceforge.scuba.smartcards.CardService;
import credentials.keys.PrivateKey;
import credentials.spec.IssueSpecification;
import credentials.spec.VerifySpecification;
import credentials.util.LogEntry;

public abstract class BaseCredentials implements Credentials {
	protected CardService cs = null;

	public BaseCredentials() {
	}

	/**
	 * Create a credential class.
	 *
	 * @param cs The cardservice to use when running the protocols.
	 * @throws CredentialsException
	 */
	public BaseCredentials(CardService cs) {
		this.cs = cs;
	}

	/**
	 * Get a list of credentials available on the card.
	 * 
	 * @return list of credential identifiers.
	 */
	public List<Integer> getCredentials() {
		List<Integer> list = new Vector<Integer>();
		
		return list;
	}
	
	/**
	 * Get the attribute values stored on the card for the given credential.
	 *  
	 * @param credential identifier.
	 * @return attributes for the given credential.
	 */
	public Attributes getAttributes(short credentialID) {
		Attributes attributes = new Attributes();
		
		return attributes;
	}
	
	/**
	 * Get the transaction log from the card.
	 * 
	 * @return list of log entries from the card.
	 */
	public List<LogEntry> getLog() {
		List<LogEntry> log = new Vector<LogEntry>();
		
		return log;
	}
	
	@Override
	public void issue(IssueSpecification specification, PrivateKey isk, Attributes values)
			throws CredentialsException {
		// TODO Auto-generated method stub

	}

	@Override
	public IssueSpecification issueSpecification() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Attributes verify(VerifySpecification specification)
			throws CredentialsException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public VerifySpecification verifySpecification() {
		// TODO Auto-generated method stub
		return null;
	}

}
