package Driver;

public class Tuple 
{
	public static final String myClassName = "Tuple";
	
	public volatile String name = "";
	public volatile int value = 0;
	
	public Tuple(String Name, int val)
	{
		name = Name;
		value = val;
	}
	
	public boolean increment()
	{
		try
		{
			++value;
		}
		catch(Exception e)
		{
						
		}
		
		return true;
	}
}
