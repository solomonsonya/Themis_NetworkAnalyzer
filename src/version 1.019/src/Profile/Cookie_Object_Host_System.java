/**
 * @author Solomon Sonya
 */
package Profile;

import java.awt.BorderLayout;
import java.io.*;
import java.net.Socket;
import java.util.LinkedList;
import java.util.TreeMap;
import java.util.*;

import Interface.*;
import javax.swing.*;
import Interface.*;
import Driver.*;
import Encryption.Encryption;
import Parser.*;
import Profile.Resolution;
import Profile.SOURCE;
import ResolutionRequest.ResolutionRequest_ServerSocket;
import ResolutionRequest.ResolutionRequest_ThdSocket;
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
	
	public volatile String []arrJTableRow = new String[18];
	
	public static volatile LinkedList<Cookie_Object_Host_System> list_cookie_object_host_system = new LinkedList<Cookie_Object_Host_System>();
	
	public Cookie_Object_Host_System(File fleCookie)
	{
		try
		{
			fle = fleCookie;
			list_cookie_object_host_system.add(this);
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
	
	
	public String get_display_data(String delimiter)
	{
		try
		{
			return 	"Cookie Name: " + cookie_name+ delimiter + 
					"Cookie Value: " + cookie_value+ delimiter + 
					"Web Server: " + web_server+ delimiter + 
					"Cookie File Creation: " + creation+ delimiter + 
					"Cookie File Last Accessed: " + last_accessed+ delimiter + 
					"Cookie File Last Modified: " + last_modified+ delimiter + 
					"Host Machine IP Address: " + ip_address+ delimiter + 
					"User Name: " + user_name+ delimiter + 
					"Host Name: " + host_name+ delimiter + 					
					"Flags: " + flags+ delimiter + 
					"Cookie Expiration Eime (low): " + expiration_time_low+ delimiter + 
					"Cookie Expiration Time (high): " + expiration_time_high+ delimiter + 
					"Cookie Creation Time (low): " + creation_time_low+ delimiter + 
					"Cookie Creation Time (high): " + creation_time_high+ delimiter + 
					"Record Number: " +  record_number + delimiter + 
					"Cookie File Name: " + file_name+ delimiter + 
					"Cookie File Path: " + file_path; 

		}
		catch(Exception e)
		{
			driver.eop(myClassName, "get_display_data", e);
		}
		
		return this.cookie_value;
	}
	
	
	
	
	
	
	
	
	
	
	
}
