package credentials.util;

public class Timestamp {
	public static long getWeek() {
		return System.currentTimeMillis() / 7 / 24 / 60 / 60 / 1000; 
	}
	
	public static long getWeekOffset(int offset) {
		return getWeek() + offset;
	}
}
