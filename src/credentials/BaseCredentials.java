package credentials;

import net.sourceforge.scuba.smartcards.CardService;
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
	public void issue(IssueSpecification specification, Attributes values)
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
