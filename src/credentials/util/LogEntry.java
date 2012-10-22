/**
 * LogEntry.java
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
 * Copyright (C) Pim Vullers, Radboud University Nijmegen, October 2012
 */

package credentials.util;

import java.util.Date;
import java.util.List;
import java.util.Vector;

public class LogEntry {

	public enum Action {
		ISSUE,
		VERIFY
	}
	
	private Date timestamp;
	private Action action;
	private short credential;
	private short disclose;
	
	/**
	 * Create a new log entry for a card transaction.
	 * 
	 * @param timestamp at which the transaction occurred.
	 * @param action that was performed.
	 * @param id of the credential involved.
	 * @param selection of attributes disclosed.
	 */
	public LogEntry(Date timestamp, Action action, short id, short selection) {
		this.timestamp = timestamp;
		this.action = action;
		this.credential = id;
		this.disclose = selection;
	}
	
	/**
	 * Get the date and time at which this transaction occurred.
	 * 
	 * @return timestamp of the tranasction.
	 */
	public Date getTimestamp() {
		return timestamp;
	}
	
	/**
	 * Get the action performed during this transaction
	 * @return
	 */
	public Action getAction() {
		return action;
	}
	
	/**
	 * Get the credential involved in this transaction.
	 * 
	 * @return identifier of the credential.
	 */
	public short getCredential() {
		return credential;
	}
	
	/**
	 * Get the list of attributes selected for disclosure during this 
	 * transaction.
	 * 
	 * @return list of attribute indices.
	 */
	public List<Integer> getSelection() {
		List<Integer> selection = new Vector<Integer>();
		
		for (int i = 0; i < 16; i++) {
			if ((disclose & (1 << i)) != 0) {
				selection.add(i);
			}
		}
		
		return selection;
	}
}
