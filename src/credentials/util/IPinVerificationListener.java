package credentials.util;

public interface IPinVerificationListener {
	
	/**
	 * Called when user-pin is required. When called the first time
	 * nr_tries_left is null. Otherwise, it indicates the previous attempt was
	 * incorrect, and instead displays the number of remaining tries.
	 * 
	 * @param nr_tries_left
	 *            Number of tries left
	 * @return The PIN entered by the user.
	 */
	public String userPinRequest(Integer nr_tries_left);
	
	/**
	 * Called to notify that user action on the pin-pad is required. Parameter
	 * nr_tries_left acts as in userPinRequest.
	 * 
	 * @param nr_tries_left
	 *            Number of tries left.
	 */
	public void pinPadPinRequired(Integer nr_tries_left);
	
	/**
	 * Called to notify that pin-pad action has been performed by the user.
	 */
	public void pinPadPinEntered();
}
