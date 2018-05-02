/**
 * Identifying an application is predicated on the notion that each destination port can only be bound by a single process. 
 * A process may bind to multiple ports, however a socket connection can only be handled by a single process. 
 * Thus, if we can tuple a destination address and a port to a process, then we can identify the application likely running on the other side
 * (assuming non-standard ports are possible with this identification) since reaching out to IP on PORT 80, it could be any process on the other
 * side handling it without prior knowledge of the domain we're reaching out to.  However, if we do know the domain, then we can reduce entropy 
 * of the application bound to that port. 
 * 
 * @author Solomon Sonya
 */

package Parser;

import Driver.*;
import Parser.Artifact;
import Profile.*;
import ResolutionRequest.*;
import java.util.*;

public class Application 
{
	public static final String myClassName = "Application";
	public static volatile Driver driver = new Driver();
	
	public static volatile TreeMap<String, Application> TREE_APPLICATION = new TreeMap<String, Application>();
	
	/**e.g. 74.158.2.5:80 to be a unique address and port, which we'll use to map to a unique application hopefully*/
	public volatile String key = "";
	public volatile String application = "";
	public volatile String protocol = "";
	public volatile String domain_name = "";
	public volatile String alert_indicator = "";
	public volatile Resolution myResolution = null; 
	public volatile LinkedList<String> list_alert = null;	
	
	public volatile TreeMap<String, SOURCE> tree_source = new TreeMap<String, SOURCE>();
	
	public volatile String IP = "", PORT = "";
	
	public static volatile boolean update_network = true;
	public volatile String data_view_summary = "";
	
	public volatile int length = 0;
	public volatile String underline = "";
	public volatile String []jtable_row = new String[7];
	
	public volatile String first_contact_time = "";
	public volatile String last_link_time = "";
	String identifying_value = "";
	
	public Application(String KEY, String ip, String port, String PROTOCOL, Resolution resolution, String identifying_string)
	{
		try
		{
			if(KEY != null)
			{
				key = KEY.toLowerCase().trim();
				myResolution = resolution;
				IP = ip;
				PORT = port;
				protocol = PROTOCOL;
				identifying_value = identifying_string;
				
				first_contact_time = driver.get_time_stamp();
				
				if(!TREE_APPLICATION.containsKey(key))
					TREE_APPLICATION.put(key,  this);
				
				
					
				setApplication();
			}
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "Constructor - 1", e);
		}
	}
	
	
	
	public boolean link_source(SOURCE ndeSource)
	{
		try
		{
			if(ndeSource == null || ndeSource.src_ip == null || ndeSource.src_ip.trim().equals(""))
				return false;
			
			if(tree_source.containsKey(ndeSource.src_ip))
				return false;
			
			tree_source.put(ndeSource.src_ip, ndeSource);
			
			update_network = true;
			
			last_link_time = driver.get_time_stamp();
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "link_source", e);
		}
		
		return false;
	}
	
	
	public boolean setApplication()
	{
		try
		{
			//perform lookup here
			if(identifying_value == null)
				identifying_value = "";
			
			identifying_value = identifying_value.trim();
			
			//
			//Chrome
			//
			if(identifying_value.toLowerCase().contains("chrome"))
				application = "Chrome";
			else if(identifying_value.toLowerCase().contains("microsoft-crypto"))
				application = "Internet Explorer";
			
			
			
			
			
			else
				application = protocol;
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "setApplication", e);
		}
		
		return false;
	}
	
	public String getApplication()
	{
		try
		{
			if(application == null || application.trim().equals(""))
				return protocol;
			
			return application;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "getApplication", e);
		}
		
		return "-//-" + application;
	}
	
	
	public String getDataViewInformation()
	{
		try
		{
			this.data_view_summary = "Application: " + application + this.underline(application.length() + 13) + "\n\n";
			
			data_view_summary = data_view_summary + "DATA:" + this.underline(5) + "\n";
			
			data_view_summary = data_view_summary + "Key: " + key + "\n";
			data_view_summary = data_view_summary + "IP: " + IP + "\n";
			data_view_summary = data_view_summary + "Port:" + PORT + "\n";
			data_view_summary = data_view_summary + "Protocol:" + this.protocol + "\n";
			data_view_summary = data_view_summary + "First Contact Time:" + first_contact_time + "\n";
			data_view_summary = data_view_summary + "Last Link Time:" + last_link_time + "\n";
			
			if(!getDomainName().trim().equals(""))
				data_view_summary = data_view_summary + "\nDomain Name:\n============\n" +this.getDomainName() + "\n\n";
			
			if(this.list_alert != null && this.list_alert.size() > 0)
			{
				data_view_summary = data_view_summary + "\nALERT:\n======\n";
				
				for(String s: list_alert)
				{
					if(s == null || s.trim().equals(""))
						continue;
					
					data_view_summary = data_view_summary + s + "\n";
				}
				
				data_view_summary = data_view_summary + "\n";
			}
			
			data_view_summary = data_view_summary + "\nSource Nodes:\n=============\n";
			
			for(SOURCE source : tree_source.values())
			{
				if(source == null || source.src_ip.trim().equals(""))
					continue;
					
				data_view_summary = data_view_summary + source.src_ip + "\n";
			}
			
			//this.get_domain_name_list("Domain Name:", " \t ", this.list_dns_query_names)
		
			return data_view_summary;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "getDataViewInformation", e);
		}
		
		return "//--//" + application;
	}
	
	
	
	
	public String underline(int len)
	{
		try
		{
			underline = "\n";
			
			for(int i = 0; i < len; i++)
			{
				underline = underline + "=";
			}
		}
		
		catch(Exception e)
		{
			driver.eop(myClassName, "underline", e);
		}
		
		return underline;
	}
	
	public String [] get_jtable_row_summary(String delimiter)
	{
		try
		{						
			jtable_row[0] = key;
			jtable_row[1] =	application;
			jtable_row[2] = protocol;
			jtable_row[3] = PORT;
			jtable_row[4] = getDomainName();
			jtable_row[5] = ""+this.tree_source.size();
			jtable_row[6] = alert_indicator;								
			
			return jtable_row;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "get_jtable_row_summary", e);
		}
		
		return jtable_row;
	}
	
	public String getDomainName()
	{
		try
		{
			if(this.domain_name == null || this.domain_name.trim().equals("") && this.myResolution != null)
			{
				return this.myResolution.get_domain_name_list("", "", myResolution.list_dns_query_names);
			}
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "getDomainName");
		}
		
		return this.domain_name;
	}
	
}
