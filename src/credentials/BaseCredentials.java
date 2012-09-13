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

import net.sourceforge.scuba.smartcards.CardService;
import credentials.keys.PrivateKey;
import credentials.spec.IssueSpecification;
import credentials.spec.VerifySpecification;

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
