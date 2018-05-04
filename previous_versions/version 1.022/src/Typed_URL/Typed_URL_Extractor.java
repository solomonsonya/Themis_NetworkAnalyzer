/**
 * The purpose of this class is to search through the registry and identify URLs that the user might have visited in the past
 *
 * @author Solomon Sonya
 */

package Typed_URL;

import Driver.*;

import java.io.*;
import java.util.*;
import java.awt.event.*;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.Statement;
import java.util.prefs.Preferences;
import com.sun.jna.platform.win32.WinReg;

import Cookie.Cookie_Object_Host_System;

import com.sun.jna.platform.win32.Advapi32Util;
import com.sun.jna.platform.win32.Crypt32Util;
import java.awt.event.*;

public class Typed_URL_Extractor extends Thread implements Runnable, ActionListener
{
	public static volatile Driver driver = new Driver();
	public static final String myClassName = "Typed_URL_Extractor";
	
	
	public static final String INTERNET_EXPLORER_REGISTRY_TYPED_URLS = "SOFTWARE\\Microsoft\\Internet Explorer\\TypedURLs";
	
	public static volatile Connection connection = null;
	LinkedList<String> list_col_names = new LinkedList<String>();
	LinkedList<String> list_col_names_data_types = new LinkedList<String>();
	
	public static final long CHROME_EPOCH_START_TIME = 11644473600000l;
	
	static Hash hash = new Hash();
	
	public static volatile boolean data_table_updated = false;
	
	public static volatile boolean ORBITER_TYPED_URL_ENABLED = true;
	public volatile boolean process_interrupt = true;
	public static volatile javax.swing.Timer tmr_orbiter = null;
	public static volatile int INTERRUPT_MILLIS = 300000;
	
	public Typed_URL_Extractor(int interrupt_millis)
	{
		try
		{			
			INTERRUPT_MILLIS = interrupt_millis;
			this.start();
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "Constructor - 1", e, true);
		}
	}

	public void run()
	{
		try
		{						
			this.tmr_orbiter = new javax.swing.Timer(INTERRUPT_MILLIS, this);
			tmr_orbiter.start();
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "run", e);
		}
	}
	
	public void actionPerformed(ActionEvent ae)
	{
		try
		{
			if(ae.getSource() == this.tmr_orbiter && this.ORBITER_TYPED_URL_ENABLED)
				process_interrupt();
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "ae", e);
		}
	}
	
	public boolean process_interrupt()
	{
		try
		{
			if(!this.ORBITER_TYPED_URL_ENABLED)
				return false;
			
			if(!this.process_interrupt)
				return false;			
			
			this.process_interrupt = false;
			
			enumerate_typed_urls(false);
									
			this.process_interrupt = true;
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "process_interrupt", e);
		}
		
		this.process_interrupt = true;
		return false;
	}
	
	public static boolean enumerate_typed_urls(boolean notify_user_if_error)
	{
		try
		{						
			enumerate_windows_internet_explorer_typed_urls();			    			
			enumerate_sqllite_db_file(Driver.fle_path_app_data_chrome_history, "urls", "Chrome", notify_user_if_error);
						
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "enumerate_typed_urls", e);
		}
		
		return false;
	}
	
	public static boolean enumerate_windows_internet_explorer_typed_urls()
	{
		try
		{
			TreeMap<String, Object> tree =  Advapi32Util.registryGetValues(WinReg.HKEY_CURRENT_USER, INTERNET_EXPLORER_REGISTRY_TYPED_URLS);
			
			for(String key : tree.keySet())
			{
				try
				{
					if(!Node_URL.tree_typed_url.containsKey("IE_" + key))
					{
						Node_URL url = new Node_URL("IE", key, ""+tree.get(key), "HKCU\\" + INTERNET_EXPLORER_REGISTRY_TYPED_URLS);
						url.is_IE_typed_URL = true;
					}
				}
				catch(Exception e)
				{
					driver.sop("registry check key " + key);
					continue;
				}
				
			}
			
			
			return true;
		}
		
		catch(Exception e)
		{
			driver.eop(myClassName, "enumerate_windows_internet_explorer_typed_urls", e);
		}
		
		return false;
	}
	
	
	public static boolean enumerate_sqllite_db_file(File file, String table, String type, boolean notify_user_if_error)
	{
		try
		{		
			if(file == null || !file.exists() || !file.isFile())
				return false;
			
			String location = file.getCanonicalPath();
			
			//determine structure of db file
			//enumerate_db_schema(file, "urls");
			
			//we have the following col headers in the cookie file!
			/**
			 	
			 	for urls table
			 	==============
			 	
			 	id - 4 - INTEGER
				url - 12 - LONGVARCHAR
				title - 12 - LONGVARCHAR
				visit_count - 4 - INTEGER
				typed_count - 4 - INTEGER
				last_visit_time - 4 - INTEGER
				hidden - 4 - INTEGER
			 
			 
			 	for visits table:
			 	=================
			 	
			  	id - 4 - INTEGER
				url - 4 - INTEGER
				visit_time - 4 - INTEGER
				from_visit - 4 - INTEGER
				transition - 4 - INTEGER
				segment_id - 4 - INTEGER
				visit_duration - 4 - INTEGER
			 */
			
			connection = DriverManager.getConnection("jdbc:sqlite:" + file.getCanonicalPath());
				
			//driver.sop("SQLite connection opened to " + file.getCanonicalPath() + ".  Attempting to parse table now...");
			
						
			Statement stmt = connection.createStatement();
			
			
			String query = "SELECT * FROM " + table;
			//String query = "SELECT url FROM urls ORDER BY last_visit_time DESC";
			ResultSet result_set = stmt.executeQuery(query);
									
						
			//parse results
			int count = 0;
			String key = "";
			
			
			
			while(result_set.next())
			{
				try
				{
	
					key = "Chrome_" + hash.hashMessage_MD5(result_set.getString("url"), -1, false);
					
					Node_URL url  = null;

					if(Node_URL.tree_typed_url.containsKey(key))
						url = Node_URL.tree_typed_url.get(key);

					if(url == null)
					{
						url = new Node_URL("Chrome", key, result_set.getString("url"), location);
						url.is_chrome_history_file = true;
						
						data_table_updated = true;
					}

					url.title = result_set.getString("title");
					url.visit_count = result_set.getString("visit_count");
					url.typed_count = result_set.getString("typed_count");
					url.last_visit_time_webkit = result_set.getString("last_visit_time");
					url.hidden = result_set.getString("hidden");

					//convert visit time
					if(url.last_visit_time_webkit != null && !url.last_visit_time_webkit.trim().equals("0"))
					{
						long last_visit_time_webkit = Long.parseLong(url.last_visit_time_webkit.trim());

						long last_visit_time_epoch = last_visit_time_webkit/1000-CHROME_EPOCH_START_TIME;

						if(last_visit_time_epoch > 0)
						{
							url.last_visit_time_epoch = ""+last_visit_time_epoch;
							url.last_visit_time = (driver.get_time_stamp(last_visit_time_epoch));
						}
					}
				}
															
				
				catch(Exception e)
				{
					driver.sop("reading value [" + count + "]" );
					continue;
				}
			}
			
			Node_URL.update_required = true;
			
			try	{	if(connection != null) connection.close();	}	catch(Exception e){}
			return true;
		}
		catch(Exception e)
		{
			try
			{
				if(e.getLocalizedMessage().toLowerCase().contains("busy") || e.getLocalizedMessage().toLowerCase().contains("locked"))
				{
					if(!notify_user_if_error)
						return false;
					
					String msg = "\nPUNT! I am unable to access the database at this moment. It appeaers to be busy or locked by another programming accessing the resource. If necessary, you may consider shutting down Chrome to allow me access to this database file.";
					
					driver.directive(msg);		
					
					return false;
				}
			}
			catch(Exception ee)
			{
				
			}
			
			driver.eop(myClassName, "enumerate_sqllite_db_file", e);
		}
		
		try	{	if(connection != null) connection.close();	}	catch(Exception e){}
		return false;
	}
	
	
	public boolean enumerate_db_schema(File file, String table)
	{
		try
		{
			if(file == null || !file.isFile() || !file.exists())
			{
				driver.directive("PUNT! File does not appear to exist: " + file);
				return false;
			}
			
			if(connection != null)
			{
				try
				{
					connection.close();
				}
				catch(Exception e)
				{
					
				}
			}
			
			connection = DriverManager.getConnection("jdbc:sqlite:" + file.getCanonicalPath());
			
			driver.directive("SQLite connection opened to " + file.getCanonicalPath() + ".  Enumerating schema now...");
			
			//
			//determine the number of tables
			//
			Statement stmt = connection.createStatement();

			String query = "SELECT name FROM sqlite_master WHERE type = \"table\"";
			ResultSet result_set = stmt.executeQuery(query);
			
			//determine table structure
			ResultSetMetaData result_set_meta_data = result_set.getMetaData();
			driver.directive("Number tables: " + result_set_meta_data.getColumnCount() + "; data --> " + result_set_meta_data.getColumnName(1) + " - " + result_set_meta_data.getColumnType(1) + " - " + result_set_meta_data.getColumnTypeName(1));			
			
			//
			//list for a particular table
			//
			 stmt = connection.createStatement();

			 query = "SELECT * FROM " + table;
			 result_set = stmt.executeQuery(query);
			
			//determine table structure
			 result_set_meta_data = result_set.getMetaData();
			int col_count = result_set_meta_data.getColumnCount();
			
			driver.directive("\ntable name: [" + table + "] col count: " + col_count + ". Col Names below:");			
			
			try
			{
				for(int i = 1; i <= col_count; i++)
				{
					list_col_names.add(result_set_meta_data.getColumnName(i));
					list_col_names_data_types.add(result_set_meta_data.getColumnName(i) + " - " + result_set_meta_data.getColumnType(i) + " - " + result_set_meta_data.getColumnTypeName(i));
				}	
				
//				for(String col_name : list_col_names)
//					driver.directive(col_name);
				for(String col_name : list_col_names_data_types)
					driver.directive("\t" + col_name);
			}
			catch(Exception e)
			{
				driver.eop(myClassName, "enumerate_db_schema", e);
			}
			
			
			if(connection != null)
			{
				try
				{
					connection.close();
				}
				catch(Exception e)
				{
					
				}
			}
			return true;
		}
		
		catch(Exception e)
		{
			if(e.getLocalizedMessage().toLowerCase().contains("busy") || e.getLocalizedMessage().toLowerCase().contains("locked"))
			{
				String msg = "\nPUNT!!! I am unable to access the database at this moment. It appeaers to be busy or locked by another programming accessing the resource. If necessary, you may consider shutting down Chrome to allow me access to this database file.";
				
				driver.directive(msg);										
			}
			
			else
				driver.eop(myClassName, "enumerate_db_schema", e);
		}
		
		if(connection != null)
		{
			try
			{
				connection.close();
			}
			catch(Exception e)
			{
				
			}
		}
		return false;
	}
	
	
	public String decrypt_value(byte[] cookie)
	{
		try
		{
			if(cookie == null || cookie.length < 1)
				return "";
			
			if(driver.isWindows)
			{
				 try
				 {
					 byte[] decrypted_bytes = Crypt32Util.cryptUnprotectData(cookie);
					 
					 return new String(decrypted_bytes);
				 } 
				 
				 catch (Exception e)
				 {
					 //perhaps not encrypted, try returning byte conversion directly to string
					 return new String(cookie);
				 }
			}
			
			//special thanks to Ben Holland https://stackoverflow.com/questions/33629474/reading-and-inserting-chrome-cookies-java			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "decrypt_value", e);
		}
		
		try
		{
			return (new String(cookie));
		}
		
		catch(Exception e)
		{
			
		}
		
		return "";
	}
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
}




