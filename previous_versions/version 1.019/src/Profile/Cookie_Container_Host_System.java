/**
 * @author Solomon Sonya
 */
package Profile;

import java.awt.BorderLayout;
import java.io.*;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributeView;
import java.nio.file.attribute.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.LinkedList;
import java.util.TreeMap;
import java.util.concurrent.TimeUnit;
import java.util.*;

import Interface.*;

import javax.naming.directory.BasicAttributes;
import javax.swing.*;
import Interface.*;
import Driver.*;
import Driver.Driver;
import Encryption.Encryption;
import Parser.*;
import Profile.Resolution;
import Profile.SOURCE;
import ResolutionRequest.ResolutionRequest_ServerSocket;
import ResolutionRequest.ResolutionRequest_ThdSocket;
import Sensor.*;

import java.sql.*;
import java.sql.Date;
import java.text.SimpleDateFormat;
import java.time.Duration;
import java.time.Instant;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;


import com.sun.jna.platform.win32.*;


public class Cookie_Container_Host_System 
{
	public static final String myClassName = "Cookie_Container_Host_System";
	public static volatile Driver driver = new Driver();

	public volatile boolean notify_user_of_empty_cookies = false;
	public volatile File fle = null;
	
	LinkedList<String> list_col_names = new LinkedList<String>();
	LinkedList<String> list_col_names_data_types = new LinkedList<String>();
	
	public volatile Connection connection = null;
	
	SimpleDateFormat dateFormat_yyyy_mm_dd_hh_mm_ss_colon = new SimpleDateFormat("yyyy-MM-dd-HHmm:ss");
	
	public Cookie_Container_Host_System(File fleCookie)
	{
		try
		{
			fle = fleCookie;
			
			enumerate_windows_system_cookies(fle);
			
			//Chrome: C:\Users\Solomon Sonya\AppData\Local\Google\Chrome\User Data\Default/Cookies
			//chrome is in an sqllite3 database, encrypted, at C:\Users\<user_name>\AppData\Local\Google\Chrome\User Data\Profile 1
			//note, profile could be profile2, profile3, etc
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "Constructor - 1", e);
		}
	}
	
	public Cookie_Container_Host_System(File fleCookie, boolean this_is_sqllite_database_file, boolean notify_user_of_empty_cookie)
	{
		try
		{
			notify_user_of_empty_cookies = notify_user_of_empty_cookie;
			fle = fleCookie;
			
			if(this_is_sqllite_database_file)
				enumerate_sqllite_cookie_db_file(fle);
			else			
				enumerate_windows_system_cookies(fle);
			
			//Chrome: C:\Users\Solomon Sonya\AppData\Local\Google\Chrome\User Data\Default\Cookies
			//chrome is in an sqllite3 database, encrypted, at C:\Users\<user_name>\AppData\Local\Google\Chrome\User Data\Profile 1
			//note, profile could be profile2, profile3, etc
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "Constructor - 1", e);
		}
	}
	
	public boolean enumerate_db_schema(File file, String table)
	{
		try
		{
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
			
			connection = DriverManager.getConnection("jdbc:sqlite:" + Driver.fle_path_app_data_chrome_cookies.getCanonicalPath());
			
			driver.sop("SQLite connection opened to " + file.getCanonicalPath() + ".  Enumerating schema now...");
			
						
			Statement stmt = connection.createStatement();
			//stmt.setQueryTimeout(60);
			String query = "SELECT * FROM " + table;
			ResultSet result_set = stmt.executeQuery(query);
			
			//determine table structure
			ResultSetMetaData result_set_meta_data = result_set.getMetaData();
			int col_count = result_set_meta_data.getColumnCount();
			driver.directive("col count: " + col_count);			
			
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
					driver.directive(col_name);
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
	
	public boolean enumerate_sqllite_cookie_db_file(File file)
	{
		try
		{						
			//determine structure of db file
			//enumerate_db_schema(file, "cookies");
			
			//we have the following col headers in the cookie file!
			/**
			  	creation_utc 	- 4 - INTEGER
				host_key 		- 12 - TEXT
				name 			- 12 - TEXT
				value 			- 12 - TEXT
				path 			- 12 - TEXT
				expires_utc 	- 4 - INTEGER
				secure 			- 4 - INTEGER
				httponly 		- 4 - INTEGER
				last_access_utc - 4 - INTEGER
				has_expires 	- 4 - INTEGER
				persistent 		- 4 - INTEGER
				priority 		- 4 - INTEGER
				encrypted_value - 2004 - BLOB
				firstpartyonly 	- 4 - INTEGER
			 */
			
			connection = DriverManager.getConnection("jdbc:sqlite:" + Driver.fle_path_app_data_chrome_cookies.getCanonicalPath());
				
			//driver.sop("SQLite connection opened to " + file.getCanonicalPath() + ".  Attempting to parse table now...");
			
						
			Statement stmt = connection.createStatement();
			//stmt.setQueryTimeout(60);
			String query = "SELECT * FROM cookies";
			ResultSet result_set = stmt.executeQuery(query);
									
			String creation_utc = null;
			String creation_utc_converted = null;
			String host_key = "";
			String name = "";
			String value = "";
			String path = "";
			String expires_utc = null;
			boolean secure = false;
			boolean httponly = false;
			String last_access_utc = null;
			boolean has_expires = false;
			boolean persistent = false;
			int priority = 0;
			byte[] encrypted_value = null;
			String decrypted_cookie = null;
			boolean firstpartyonly = false;
			
			//parse results
			int cookie_count = 0;
			
			while(result_set.next())
			{
				try
				{
					++cookie_count;
															
										
					host_key = result_set.getString("host_key");
					
					if(host_key.startsWith("."))
						host_key = host_key.substring(1).trim();
					
					name = result_set.getString("name");
					value = result_set.getString("value");
					path = result_set.getString("path");					
					
					creation_utc = result_set.getString("creation_utc");										
					last_access_utc = result_set.getString("last_access_utc");
					expires_utc = result_set.getString("expires_utc");
					
					secure = result_set.getBoolean("secure");
					httponly = result_set.getBoolean("httponly");
					has_expires = result_set.getBoolean("has_expires");
					firstpartyonly = result_set.getBoolean("firstpartyonly");					
					//priority = result_set.getInt(priority);					
					encrypted_value = result_set.getBytes("encrypted_value");					
					decrypted_cookie = decrypt_cookie(encrypted_value);
					
					//
					//POPULATE THE COOKIE!
					//
					Cookie_Object_Host_System cookie = new Cookie_Object_Host_System(null);
					
					cookie.type_sqlite_db_file = true;
					cookie.ip_address = driver.myIPAddress;
					cookie.user_name = driver.user_name;
					cookie.host_name = driver.host_name;
					cookie.file_name = file.getName();
					cookie.file_path = file.getCanonicalPath();
					cookie.cookie_name = name;
					cookie.cookie_value = decrypted_cookie;
					cookie.web_server = host_key;
					cookie.flags = "";
					cookie.expiration_time_low = "";
					cookie.expiration_time_high = expires_utc;
					cookie.creation_time_low = "";
					cookie.creation_time_high = creation_utc;
					cookie.creation = creation_utc;
					cookie.last_accessed = last_access_utc;
					cookie.last_modified = last_access_utc;
					cookie.record_number = cookie_count;
					
					
					cookie.arrJTableRow[0] = driver.myIPAddress;
					cookie.arrJTableRow[1] = driver.user_name;
					cookie.arrJTableRow[2] = driver.host_name;
					cookie.arrJTableRow[3] = cookie.creation;
					cookie.arrJTableRow[4] = cookie.last_accessed;
					cookie.arrJTableRow[5] = cookie.last_modified;
					cookie.arrJTableRow[6] = cookie.cookie_name;
					cookie.arrJTableRow[7] = cookie.cookie_value;
					cookie.arrJTableRow[8] = cookie.web_server;
					cookie.arrJTableRow[9] = cookie.flags;
					cookie.arrJTableRow[10] = cookie.expiration_time_low;
					cookie.arrJTableRow[11] = cookie.expiration_time_high;
					cookie.arrJTableRow[12] = cookie.creation_time_low;
					cookie.arrJTableRow[13] = cookie.creation_time_high;
					cookie.arrJTableRow[14] = ""+cookie.record_number;
					cookie.arrJTableRow[15] = cookie.file_name;
					cookie.arrJTableRow[16] = cookie.file_path;
					cookie.arrJTableRow[17] = "Chrome Cookie DB table";
				
						
					/*driver.directive("\n===================================");
					driver.directive("creation_utc: " + creation_utc);
					driver.directive("creation_utc_converted: " + creation_utc_converted);
					driver.directive("host_key: " + host_key);
					driver.directive("name: " + name);
					driver.directive("value: " + value);
					driver.directive("path: " + path);
					driver.directive("expires_utc: " + expires_utc);
					driver.directive("secure: " + secure);
					driver.directive("httponly: " + httponly);
					driver.directive("last_access_utc: " + last_access_utc);
					driver.directive("has_expires: " + has_expires);
					driver.directive("persistent: " + persistent);
					driver.directive("priority: " + priority);
					driver.directive("encrypted_value: " + new String(encrypted_value));
					driver.directive("decrypted_cookie: " + decrypted_cookie);
					driver.directive("firstpartyonly: " + firstpartyonly);*/
					
				}
				catch(Exception e)
				{
					driver.sop("reading cookie [" + cookie_count + "]" );
					e.printStackTrace(System.out);
					continue;
				}
			}
				
			
			try	{	if(connection != null) connection.close();	}	catch(Exception e){}
			return true;
		}
		catch(Exception e)
		{
			try
			{
				if(e.getLocalizedMessage().toLowerCase().contains("busy") || e.getLocalizedMessage().toLowerCase().contains("locked"))
				{
					String msg = "\nPUNT! I am unable to access the database at this moment. It appeaers to be busy or locked by another programming accessing the resource. If necessary, you may consider shutting down Chrome to allow me access to this database file.";
					
					driver.directive(msg);
					
					if(notify_user_of_empty_cookies)
						driver.jop_Error(msg, false);
				}
			}
			catch(Exception ee)
			{
				
			}
			
			driver.eop(myClassName, "enumerate_sqllite_cookie_db_file", e, true);
		}
		
		try	{	if(connection != null) connection.close();	}	catch(Exception e){}
		return false;
	}

	public String decrypt_cookie(byte[] cookie)
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
			/*if(OS.isWindows()){
                try {
                    decryptedBytes = Crypt32Util.cryptUnprotectData(encryptedCookie.getEncryptedValue());
                } catch (Exception e){
                    decryptedBytes = null;
                }
            } else if(OS.isLinux()){
                try {
                    byte[] salt = "saltysalt".getBytes();
                    char[] password = "peanuts".toCharArray();
                    char[] iv = new char[16];
                    Arrays.fill(iv, ' ');
                    int keyLength = 16;

                    int iterations = 1;

                    PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, keyLength * 8);
                    SecretKeyFactory pbkdf2 = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");

                    byte[] aesKey = pbkdf2.generateSecret(spec).getEncoded();

                    SecretKeySpec keySpec = new SecretKeySpec(aesKey, "AES");

                    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                    cipher.init(Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec(new String(iv).getBytes()));

                    // if cookies are encrypted "v10" is a the prefix (has to be removed before decryption)
                    byte[] encryptedBytes = encryptedCookie.getEncryptedValue();
                    if (new String(encryptedCookie.getEncryptedValue()).startsWith("v10")) {
                        encryptedBytes = Arrays.copyOfRange(encryptedBytes, 3, encryptedBytes.length);
                    }
                    decryptedBytes = cipher.doFinal(encryptedBytes);
                } catch (Exception e) {
                    decryptedBytes = null;
                }
            } else if(OS.isMac()){
                // access the decryption password from the keyring manager
                if(chromeKeyringPassword == null){
                    try {
                        chromeKeyringPassword = getMacKeyringPassword("Chrome Safe Storage");
                    } catch (IOException e) {
                        decryptedBytes = null;
                    }
                }
                try {
                    byte[] salt = "saltysalt".getBytes();
                    char[] password = chromeKeyringPassword.toCharArray();
                    char[] iv = new char[16];
                    Arrays.fill(iv, ' ');
                    int keyLength = 16;

                    int iterations = 1003;

                    PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, keyLength * 8);
                    SecretKeyFactory pbkdf2 = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");

                    byte[] aesKey = pbkdf2.generateSecret(spec).getEncoded();

                    SecretKeySpec keySpec = new SecretKeySpec(aesKey, "AES");

                    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                    cipher.init(Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec(new String(iv).getBytes()));

                    // if cookies are encrypted "v10" is a the prefix (has to be removed before decryption)
                    byte[] encryptedBytes = encryptedCookie.getEncryptedValue();
                    if (new String(encryptedCookie.getEncryptedValue()).startsWith("v10")) {
                        encryptedBytes = Arrays.copyOfRange(encryptedBytes, 3, encryptedBytes.length);
                    }
                    decryptedBytes = cipher.doFinal(encryptedBytes);
                } catch (Exception e) {
                    decryptedBytes = null;
                }
            }*/
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "decrypt_cookie", e);
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
	
	public boolean enumerate_windows_system_cookies(File file)
	{
		try
		{
			if(file == null ||!file.exists() || !file.isFile())
				return false;
			
			//incremented each *
			int record_number = 0;
			
			//continue reading until * is found indicating a new record
			String creation_date = "";
			String last_accessed = "";
			String last_modified = "";
			String cookie_name = "";
			String cookie_value = "";
			String web_server = "";
			String flags = "";
			String expiration_time_low = "";
			String expiration_time_high = "";
			String creation_time_low = "";
			String creation_time_high = "";
			String file_name = file.getName();
			String file_path = file.getCanonicalPath();
			
			try
			{
				BasicFileAttributeView  basic_file_attr_view    = Files.getFileAttributeView(FileSystems.getDefault().getPath(file.getCanonicalPath()), BasicFileAttributeView.class);
				BasicFileAttributes     attr     = basic_file_attr_view.readAttributes();
				
				creation_date = driver.getTime_Specified_Hyphenated_with_seconds_using_colon(attr.creationTime().toMillis());
				last_accessed = driver.getTime_Specified_Hyphenated_with_seconds_using_colon(attr.lastAccessTime().toMillis());
				last_modified = driver.getTime_Specified_Hyphenated_with_seconds_using_colon(attr.lastModifiedTime().toMillis());
				
			}
			catch(Exception ee){}
			
			BufferedReader brIn = new BufferedReader(new FileReader(fle));
			String line = "";
			
			while((line = brIn.readLine()) != null)
			{
				try
				{
					line = line.trim();
					
					if(line.equals(""))
						continue;
					
					if(cookie_name.trim().equals(""))
						cookie_name = line;
					else if(cookie_value.trim().equals(""))
						cookie_value = line;
					else if(web_server.trim().equals(""))
						web_server = line;
					else if(flags.trim().equals(""))
						flags = line;
					else if(expiration_time_low.trim().equals(""))
						expiration_time_low = line;
					else if(expiration_time_high.trim().equals(""))
						expiration_time_high = line;
					else if(creation_time_low.trim().equals(""))
						creation_time_low = line;
					else if(creation_time_high.trim().equals(""))
						creation_time_high = line;
					
					else if(line.trim().equals("*"))
					{
						++record_number;
						
						/*driver.directive(cookie_name);
						driver.directive(cookie_value);
						driver.directive(web_server);
						driver.directive(flags);
						driver.directive(expiration_time_low);
						driver.directive(expiration_time_high);
						driver.directive(creation_time_low);
						driver.directive(creation_time_high);*/
						
						
						
						
						
						//create and store the new node
						if(web_server != null && !web_server.trim().equals("") && cookie_value != null && !cookie_value.trim().equals(""))
						{
							Cookie_Object_Host_System cookie = new Cookie_Object_Host_System(fle);
							
							cookie.type_flat_text_file = true;
							cookie.ip_address = driver.myIPAddress;
							cookie.user_name = driver.user_name;
							cookie.host_name = driver.host_name;
							cookie.file_name = file_name;
							cookie.file_path = file_path;
							cookie.cookie_name = cookie_name;
							cookie.cookie_value = cookie_value;
							cookie.web_server = web_server;
							cookie.flags = flags;
							cookie.expiration_time_low = expiration_time_low;
							cookie.expiration_time_high = expiration_time_high;
							cookie.creation_time_low = creation_time_low;
							cookie.creation_time_high = creation_time_high;
							cookie.creation = creation_date;
							cookie.last_accessed = last_accessed;
							cookie.last_modified = last_modified;
							cookie.record_number = record_number;
							
							
							cookie.arrJTableRow[0] = driver.myIPAddress;
							cookie.arrJTableRow[1] = driver.user_name;
							cookie.arrJTableRow[2] = driver.host_name;
							cookie.arrJTableRow[3] = creation_date;
							cookie.arrJTableRow[4] = last_accessed;
							cookie.arrJTableRow[5] = last_modified;
							cookie.arrJTableRow[6] = cookie_name;
							cookie.arrJTableRow[7] = cookie_value;
							cookie.arrJTableRow[8] = web_server;
							cookie.arrJTableRow[9] = flags;
							cookie.arrJTableRow[10] = expiration_time_low;
							cookie.arrJTableRow[11] = expiration_time_high;
							cookie.arrJTableRow[12] = creation_time_low;
							cookie.arrJTableRow[13] = creation_time_high;
							cookie.arrJTableRow[14] = ""+record_number;
							cookie.arrJTableRow[15] = file_name;
							cookie.arrJTableRow[16] = file_path;
							cookie.arrJTableRow[17] = "flat text file";
						}
						
						//reset values
						cookie_name = "";
						cookie_value = "";
						web_server = "";
						flags = "";
						expiration_time_low = "";
						expiration_time_high = "";
						creation_time_low = "";
						creation_time_high = "";
						
					}
				}
				
				catch(Exception e)
				{
					//reset values
					cookie_name = "";
					cookie_value = "";
					web_server = "";
					flags = "";
					expiration_time_low = "";
					expiration_time_high = "";
					creation_time_low = "";
					creation_time_high = "";
					
					continue;
				}
				
				
				
				
			}
			
			try	{	brIn.close();}catch(Exception e){}
			
			return true;
		}
		catch(Exception e)
		{
			//driver.eop(myClassName, "enumerate_cookie", e);
			driver.sop("Invalid Windows System cookie format in file [" + file + "]");
		}
		
		return false;
	}
	
	
	
	
	
	
	
	
	
	
	
	
}
