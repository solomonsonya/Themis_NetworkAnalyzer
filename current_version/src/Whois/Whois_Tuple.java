/**
 * Container to hold various whois objects that are linked by the same key. 
 * 
 * For example, consider a domain IP address that is used to host several virtual hosts.  
 * 
 * This same IP should return all whois that could be linked to it
 * 
 * @author Solomon Sonya
 */


package Whois;

import Driver.*;
import java.util.*;

public class Whois_Tuple 
{
	public static final String myClassName = "Whois_Tuple";
	public static Driver driver = new Driver();

	
	public volatile LinkedList<Whois> list = new LinkedList<Whois>();
	
	public String key = "";
	
	public Whois_Tuple(String KEY, Whois whois)
	{
		try
		{
			if(KEY != null && !KEY.trim().equals("") && whois != null)
			{
				list.add(whois);
				key = KEY;							
			}
			
		}
		
		catch(ConcurrentModificationException cme)
		{
			driver.sop("Punt... I am updating the list...");
		}
		
		catch(Exception e)
		{
			driver.eop(myClassName, "Constructor - 1", e);
		}
	}
	
	
	public boolean add(Whois whois)
	{
		try
		{
			if(this.list.contains(whois))
				return false;
			
			this.list.add(whois);			
			
			return true;
		}
		catch(ConcurrentModificationException cme)
		{
			driver.sop("Standby... I am updating the list...");
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "add", e);
		}
		
		return false;
	}
	
	
	
	
	
	
	
	
	
	
	
	
	
}
