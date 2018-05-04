/**
 * @author Solomon Sonya
 */
package Cookie;

import java.awt.BorderLayout;
import java.io.*;
import java.net.Socket;
import java.util.LinkedList;
import java.util.TreeMap;
import java.util.*;

import Driver.*;
import Encryption.*;
import Sensor.*;

public class Cookie_Object_Host_System 
{
	public static final String myClassName = "Cookie_Object_Host_System";
	public static volatile Driver driver = new Driver();

	public volatile File fle = null;
	
	/**
	 * to indicate the type of data to retrieve - this one says the cookie type is microsoft ie's flat text file cookies
	 */
	public volatile boolean type_flat_text_file = false;
	public volatile boolean type_sqlite_db_file = false;
	
	public volatile String creation = "";
	public volatile String last_accessed = "";
	public volatile String last_modified = "";
	public volatile String ip_address = "";
	public volatile String user_name = "";
	public volatile String host_name = "";
	public volatile String cookie_name = "";
	public volatile String cookie_value = "";
	public volatile String web_server = "";
	public volatile String flags = "";
	public volatile String expiration_time_low = "";
	public volatile String expiration_time_high = "";
	public volatile String creation_time_low = "";
	public volatile String creation_time_high = "";
	public volatile int record_number = 1;
	public volatile String file_name = "";
	public volatile String file_path = "";
	public volatile String cookie_type = "flat text file";
	
	public volatile String []arrJTableRow = new String[18];
	
	//public static volatile LinkedList<Cookie_Object_Host_System> list_cookie_object_host_system = new LinkedList<Cookie_Object_Host_System>();
	public static volatile TreeMap<String, Cookie_Object_Host_System> tree_COOKIE = new TreeMap<String, Cookie_Object_Host_System>();
	
	
	public Cookie_Object_Host_System(File fleCookie)
	{
		try
		{
			fle = fleCookie;
			
			/*if(fle != null && fle.exists())
			{
				if(!tree_COOKIE.containsKey(fle.getName()))
				{
					tree_COOKIE.put(fle.getName(), this);
				}
			}*/
			
			//this is not an infinite add. All contents are cleared in update_cookies mtd before getting here
			//list_cookie_object_host_system.add(this);
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "Constructor - 1", e);
		}
	}
	
	public String [] get_jtable_row()
	{
		try
		{
			return arrJTableRow;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "get_jtable_row", e);
		}
		
		return arrJTableRow;
	}
	
	public static String get_cookie_header(String delimiter)
	{
		try
		{
			delimiter = delimiter + " ";
			
			return	"Cookie Name:  " + delimiter +  
					"Cookie Value:  " + delimiter +  
					"Web Server:  " + delimiter +  
					"Cookie File Creation:  " + delimiter +  
					"Cookie File Last Accessed:  " + delimiter +  
					"Cookie File Last Modified:  " + delimiter +  
					"Host Machine IP Address:  " + delimiter +  
					"User Name:  " + delimiter +  
					"Host Name:  " + delimiter +  
					"Cookie Flags:  " + delimiter +  
					"Cookie Expiration Eime (low):  " + delimiter +  
					"Cookie Expiration Time (high):  " + delimiter +  
					"Cookie Creation Time (low):  " + delimiter +  
					"Cookie Creation Time (high):  " + delimiter +  
					"Record Number:  " + delimiter +  
					"Cookie File Name:  " + delimiter +  
					"Cookie File Path:  " + delimiter +  
					"Cookie File Type:  " ;

		}
		catch(Exception e)
		{
			driver.eop(delimiter, "get_cookie_header", e);
		}
		
		return "Cookies...";
	}
	
	public String get_display_data(String delimiter, boolean include_header)
	{
		try
		{
			if(include_header)
			{
				return 	"Cookie Name: " + cookie_name+ delimiter + 
						"Cookie Value: " + cookie_value+ delimiter + 
						"Cookie Web Server: " + web_server+ delimiter + 
						"Cookie File Creation: " + creation+ delimiter + 
						"Cookie File Last Accessed: " + last_accessed+ delimiter + 
						"Cookie File Last Modified: " + last_modified+ delimiter + 
						"Host Machine IP Address: " + ip_address+ delimiter + 
						"User Name: " + user_name+ delimiter + 
						"Host Name: " + host_name+ delimiter + 					
						"Cookie Flags: " + flags+ delimiter + 
						"Cookie Expiration Eime (low): " + expiration_time_low+ delimiter + 
						"Cookie Expiration Time (high): " + expiration_time_high+ delimiter + 
						"Cookie Creation Time (low): " + creation_time_low+ delimiter + 
						"Cookie Creation Time (high): " + creation_time_high+ delimiter + 
						"Cookie Record Number: " +  record_number + delimiter + 
						"Cookie File Name: " + file_name+ delimiter + 
						"Cookie File Path: " + file_path + delimiter + 
						"Cookie File Type: " + cookie_type; 
			}
			
			//otw, no header
			return 	 cookie_name+ delimiter + 
					 cookie_value+ delimiter + 
					 web_server+ delimiter + 
					 creation+ delimiter + 
					 last_accessed+ delimiter + 
					 last_modified+ delimiter + 
					 ip_address+ delimiter + 
					 user_name+ delimiter + 
					 host_name+ delimiter + 
					 flags+ delimiter + 
					 expiration_time_low+ delimiter + 
					 expiration_time_high+ delimiter + 
					 creation_time_low+ delimiter + 
					 creation_time_high+ delimiter + 
					  record_number + delimiter + 
					 file_name+ delimiter + 
					 file_path + delimiter + 
					 cookie_type; 

			

		}
		catch(Exception e)
		{
			driver.eop(myClassName, "get_display_data", e);
		}
		
		return this.cookie_value;
	}
	
	
	
	
	
	
	
	
	
	
	
}
