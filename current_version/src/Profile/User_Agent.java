/**
 * Node class to keep track of unique user agents requested across the network and the nodes that requested for each user agent
 * 
 * @author Solomon Sonya
 */

package Profile;

import Driver.*;
import Whois_IDS_ResolutionRequest.Whois_IDS_ResolutionRequest_ThdSocket;
import Worker.ThdWorker;
import java.net.InetAddress;
import java.util.*;

public class User_Agent 
{
	public static final String myClassName = "User_Agent";
	public static volatile Driver driver = new Driver();
	
	public static volatile TreeMap<String, User_Agent> TREE_USER_AGENT = new TreeMap<String, User_Agent>();
	
	public volatile TreeMap<String, SOURCE> tree_source = new TreeMap<String, SOURCE>(); 
	
	public volatile String user_agent = "";
	
	public User_Agent(String User_Agent, SOURCE requestor)
	{
		try
		{
			if(User_Agent != null && !User_Agent.trim().equals(""))
			{				
				user_agent = User_Agent.toLowerCase().trim();
				
				if(!TREE_USER_AGENT.containsKey(user_agent))
				{
					TREE_USER_AGENT.put(user_agent,  this);
					link_requestor(requestor);
				}
				else
					TREE_USER_AGENT.get(user_agent).link_requestor(requestor);
			}
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "Constructor - 1", e);
		}
	}
	
	
	public boolean link_requestor(SOURCE source)
	{
		try
		{
			if(source == null || source.src_ip == null || source.src_ip.trim().equals(""))
				return false;
			
			if(!this.tree_source.containsKey(source.src_ip))
				this.tree_source.put(source.src_ip,  source);
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "link_requestor", e);
		}
		
		return false;
	}
	
	
	
	public String getSummary()
	{
		try
		{
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "getSummary", e);
		}
		
		return this.user_agent;
	}
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
}
