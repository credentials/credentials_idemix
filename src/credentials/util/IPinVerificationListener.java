/**
 * IPinVerificationListener.java
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
 * Copyright (C) Wouter Lueks, Radboud University Nijmegen, August 2012.
 */

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
