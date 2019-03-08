/**
 * Special thanks to freegeoip.net
 * 
 * @author Solomon Sonya
 */

package GEO_Location;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.*;
import java.net.*;
import java.util.*;

import javax.swing.JFileChooser;

import Driver.*;
import Process.*;
import Profile.*;
import jdk.nashorn.internal.ir.ContinueNode;

public class GEO_Location extends Thread implements Runnable, ActionListener
{	
	
	public static volatile boolean AUTOMATIC_GEO_RESOLUTION_ENABLED = false;
	
	public static volatile boolean continue_run = true;
	public static volatile int IP_API_QUERY_COUNT = 120;
	public static final int MAX_IP_API_QUERY_LIMIT_PER_MINUTE = 120;
	public volatile boolean close_socket_after_first_line_is_received = false;
	
	public volatile boolean resolution_complete = false;
	
	public static volatile LinkedList<GEO_Location> list_gaius_connections = new LinkedList<GEO_Location>();
	
	public static final String myClassName = "GEO_Location";
	public static volatile Driver driver = new Driver();
	
	public static volatile Log log_geo = null;
	public static volatile Log log_not_found = null;
	
	/**Just to indicate addresses we've started to lookup*/
	public static volatile TreeMap<String, String> TREE_ADDRESS_TO_LOOKUP = new TreeMap<String, String>();
	
	public static volatile TreeMap<String, GEO_Location> TREE_GEO_LOCATION = new TreeMap<String, GEO_Location>();
	
	public static volatile TreeMap<String, GEO_Location> TREE_NOT_FOUND = new TreeMap<String, GEO_Location>();
	
	public static volatile LinkedList<String> keys_to_remove = new LinkedList<String>();
	
	//public static final String QUERY_ADDRESS = "http://freegeoip.net/json/";
	public static final String QUERY_ADDRESS = "http://ip-api.com/json/";
			
	public static volatile String origin_latitude = "0";
	public static volatile String origin_longitude = "0";
	
	public static volatile boolean update_required = false;
	

	public static final boolean SURPRESS_ERROR_MESSAGES = false;
	public String address = "";
	public volatile String autonomous_system_name = "";
	public volatile String internet_service_provider = "";
	public volatile String org = "";
	public volatile String ip = "";
	public volatile String country_code = "";
	public volatile String country_name = "";
	public volatile String region_code = "";
	public volatile String region_name = "";
	public volatile String city = "";
	public volatile String zip_code = "";
	public volatile String time_zone = "";
	public volatile String latitude = "";
	public volatile String longitude = "";
	public volatile String metro_code = "";	
	public volatile String geo_string = "";
	
	public volatile String network = "";
	public volatile String continent_code = "";
	public volatile String continent_name = "";
	
	
	javax.swing.Timer tmr_update_resolutions = null;
	public volatile boolean interrupt_constructor = false;
	public int secs_to_interrupt = 60*1000;
	public static volatile boolean process_geo_lookup = true;
	
	public volatile String map_details = "";
	
	public String [] array = new String[12];
	
	public volatile boolean handle_interrupt_read_file = true;
	public volatile javax.swing.Timer tmr_import = null;
	public volatile File fleImport = null;
	public volatile boolean import_file = false;
	public volatile BufferedReader brImportFile;
	public volatile String line_import = "";
	public volatile String lower = "";
	public volatile int num_lines_read = 0;
	public volatile boolean is_called_from_import_thread = false;
	
	/**74.241.4.4*/
	public static final String external_ip_address_resolution_server_address_0 = "http://checkip.amazonaws.com/";
	
	/**74.241.4.4*/ 
	public static final String external_ip_address_resolution_server_address_1 = "https://api.ipify.org/";
	/**e.g. {"as":"AT&T","city":"Baltimore","country":"United States","countryCode":"US","isp":"AT&T","org":"AT&T","query":"74.241.4.4","region":"MD","regionName":"Maryland","status":"success","timezone":"Eastern"}*/
	
	public static final String external_ip_address_resolution_server_address_2 = "http://ip-api.com/json";
	
	public volatile String GAIUS_ADDRESS = null;
	public volatile int GAIUS_PORT = -1;
	public volatile boolean GAIUS_MAINTAIN_SOCKET_CONNECTION = false;
	
	public volatile static String GLOBAL_GAIUS_CONNECTION_ADDRESS = null;
	public volatile static int GLOBAL_GAIUS_CONNECTION_PORT = -1;
	
	public volatile BufferedReader brIn_Gaius = null;
	public volatile PrintWriter pwOut_Gaius = null;
	
	public volatile long address_decimal = 0;
	long result = 0;		
	int power = 3;
	int ip_decimal = 0;
		
	public GEO_Location()
	{
		try
		{
			this.resolve_self(0);		
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "Constructor - null", e);
		}
	}
	
	public GEO_Location(String address, int port_if_less_than_0_I_will_open_http_connection, boolean execute_in_thread, boolean maintain_connection)
	{
		try
		{
			GAIUS_ADDRESS = address;
			GAIUS_PORT = port_if_less_than_0_I_will_open_http_connection;			
			GAIUS_MAINTAIN_SOCKET_CONNECTION = maintain_connection;
			
			if(execute_in_thread)
				this.start();
			else
				establish_socket_to_gaius();
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "Constructor - geo connection instance", e);
		}
	}
	
	/**Global interrupt, every minute or so, it will search through the list of agents without a geo resolution, and attempt to complete if the resolution isn't found or null yet...*/
	public GEO_Location(int sec_to_interrupt)
	{
		try
		{
			if(!interrupt_constructor)
			{
				
				secs_to_interrupt = sec_to_interrupt;
				
				if(secs_to_interrupt < 10)
					secs_to_interrupt = 10000;
				
				interrupt_constructor = true;
				
				this.start();
			}
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "Constructor - 1", e);
		}
	}
	
	public GEO_Location(String addr)
	{
		try
		{						
			if(addr != null && !addr.trim().equals(""))
			{
				addr = addr.toLowerCase().trim();
				address = addr;
				
				close_socket_after_first_line_is_received = true;
				
				/*if(TREE_ADDRESS_TO_LOOKUP.containsKey(addr))
				{
					//do n/t since we've already tried to resolve the address
					TREE_ADDRESS_TO_LOOKUP.put(addr,  null);
				}
				else */
				
				if(TREE_GEO_LOCATION.containsKey(addr))
				{
					//do nothing, address was found!					
				}
				else if(TREE_NOT_FOUND.containsKey(addr))//this is routinely cleared in thdworker
				{
					//again, do nothing since we've tried before, and the address was not found, or timed out before we could get a request					
				}
				else if(is_private_non_routable_ip(addr))
				{
					//once more, do nothing on private ip addresses
				}
				else
				{
					//attempt to resolve!
					this.start();
				}
			}
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "Constructor - 2", e);
		}
	}
	
	public GEO_Location(boolean start_import, File fle)
	{
		try
		{
			fleImport = fle;
			import_file = true;
			this.start();
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "Constructor - 3", e);
		}
	}
	
	public GEO_Location(String import_line, boolean this_instance_is_called_from_import_thread)
	{
		try
		{
			//process the line
			//address = import_line;
			this.process_line(import_line);
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "Constructor - 4", e);
		}
	}
	
	
	public void run()
	{
		try
		{			
			//start lookup thread
			if(this.interrupt_constructor)
			{
				tmr_update_resolutions = new javax.swing.Timer(secs_to_interrupt, this);
				tmr_update_resolutions.start();
			}
			
			else if(this.import_file)
			{
				import_file(this.fleImport);
			}
			
			else if(GAIUS_ADDRESS != null)
			{
				//connect out to the socket and then forever listen to value from the socket, process what ever is received
				establish_socket_to_gaius();
			}
			
			else //implement resolution
			{
				perform_resolution();
			}
			
			
			
			//System.gc();
		}
		
		
		
		catch(Exception e)
		{
			TREE_NOT_FOUND.put(address, null);
			
			driver.eop(myClassName, "run", e);
		}
	}
	
	public boolean perform_resolution()
	{
		try
		{
			BufferedReader brIn = null;
			PrintWriter pwOut = null;
			
			
			if(!TREE_ADDRESS_TO_LOOKUP.containsKey(address))
			{
				TREE_ADDRESS_TO_LOOKUP.put(address,  null);
			}
			
			//good reference: https://stackoverflow.com/questions/2793150/how-to-use-java-net-urlconnection-to-fire-and-handle-http-requests, https://stackoverflow.com/questions/3163693/java-urlconnection-timeout
			
			//address was not found, attempt to resolve now!
			driver.sop("Attempting to resolve GEO for: [" + address + "]");
			
			if(GLOBAL_GAIUS_CONNECTION_ADDRESS != null && GLOBAL_GAIUS_CONNECTION_PORT > -1)
			{
				//connect
				Socket skt = new Socket(GLOBAL_GAIUS_CONNECTION_ADDRESS, GLOBAL_GAIUS_CONNECTION_PORT);

				brIn = new BufferedReader(new InputStreamReader(skt.getInputStream()));
				pwOut = new PrintWriter(new OutputStreamWriter(skt.getOutputStream()), true);
				
				//send request
				pwOut.println(address);
				pwOut.flush();
				close_socket_after_first_line_is_received = true;
				
				
				String line = "";
				
				while((line = brIn.readLine()) != null)
				{
					line = line.trim();
														
					if(line.trim().equals(""))
						continue;
					
					if(line.toLowerCase().contains(driver.NO_RESULTS))
						continue;
					
					if(line.toLowerCase().contains("successfully connected to"))
						continue;
					
					process_line(line);
					
					//determine if we close the connection after the first  valid line
					if(close_socket_after_first_line_is_received)
						break;
				}
				
				try	{	brIn.close();} catch(Exception e){}
				
				
			}
			
//			else if(IP_API_QUERY_COUNT++ <= MAX_IP_API_QUERY_LIMIT_PER_MINUTE)
//			{
//				URL url = new URL(QUERY_ADDRESS + address);
//														
//				HttpURLConnection connection = (HttpURLConnection) url.openConnection();
//				HttpURLConnection.setFollowRedirects(true);
//				connection.setConnectTimeout(20 * 1000);
//				connection.setRequestMethod("GET");
//				connection.setRequestProperty("User-Agent", "Mozilla/5.0 (Windows; U; Windows NT 6.0; en-US; rv:1.9.1.2) Gecko/20180719 chrome/64.0.3282.140 (.NET CLR 3.5.30729)");
//				connection.connect();
//				
//				brIn = new BufferedReader(new InputStreamReader(connection.getInputStream()));
//			}
			
			else
			{
				//come back later...
				return false;
			}
						
			return true;
		}
		
		catch(FileNotFoundException fnef)
		{
			TREE_NOT_FOUND.put(address, null);
			driver.sop("GEO Resolution for Address [" + address + "] was not found...");
		}
		catch(IOException ioe)
		{
			//bad request 400
			TREE_NOT_FOUND.put(address, null);
		}
		
		catch(Exception e)
		{
			driver.eop(myClassName, "perform_resolution", e);
		}
		
		return false;
	}
	
	public boolean establish_socket_to_gaius()
	{
		try
		{
			if(GAIUS_ADDRESS == null || GAIUS_ADDRESS.trim().equals(""))
			{
				GAIUS_ADDRESS = GLOBAL_GAIUS_CONNECTION_ADDRESS;
			}
			
			if(GAIUS_ADDRESS == null || GAIUS_ADDRESS.trim().equals(""))
			{
				driver.directive("PUNT! Unable to establish connection to Gaius instance! Address appears to be empty");
				return false;
			}
			
			GAIUS_ADDRESS = GAIUS_ADDRESS.replaceAll("localhost", "127.0.0.1");
			
			if(!is_valid_ip_address(GAIUS_ADDRESS))
			{
				driver.directive("PUNT! Address [" + GAIUS_ADDRESS + "] does not appear to be a valid IP address! Unable to continue until valid <IP address> and <Port> are specified");
				return false;
			}
			
			if(GAIUS_PORT < 0 || GAIUS_PORT > 65535)
			{
				driver.directive("PUNT! Valid port number is missing. Unable to continue until valid <IP address> <Port> are specified");
				return false;
			}
			
			String line = "";
			
			//
			//establish HTTP CONNECTION 
			//
			if(GAIUS_PORT < 0)
			{
				//NOTE: I am stopping this routine right now, and will handle HTTP later.
				//For now, just rely on the direct socket connection
				
				//HTTP
				
				driver.sop("Attempting to establish HTTP connection to GAIUS instance at " + GAIUS_ADDRESS);
				URL url = new URL(GAIUS_ADDRESS);
				HttpURLConnection connection = (HttpURLConnection) url.openConnection();
				HttpURLConnection.setFollowRedirects(true);
				connection.setConnectTimeout(20 * 1000);
				//connection.setRequestMethod("GET");			
				connection.setRequestProperty("User-Agent", "Mozilla/5.0 (Windows; U; Windows NT 6.0; en-US; rv:1.9.1.2) Gecko/20180719 chrome/4.0.3282.140 (.NET CLR 3.5.30729)");
				connection.connect();

				brIn_Gaius = new BufferedReader(new InputStreamReader(connection.getInputStream()));
				pwOut_Gaius = new PrintWriter(new OutputStreamWriter(connection.getOutputStream()), true);
				
				
				
			}
			
			//
			//establish SOCKET CONNECTION 
			//
			else
			{
				//SOCKET CONNECTION
				
				driver.sop("Attempting to establish socket connection to GAIUS instance at " + GAIUS_ADDRESS);
				Socket skt = new Socket(GAIUS_ADDRESS, GAIUS_PORT);

				brIn_Gaius = new BufferedReader(new InputStreamReader(skt.getInputStream()));
				pwOut_Gaius = new PrintWriter(new OutputStreamWriter(skt.getOutputStream()), true);
				
				driver.directive("Connection successfully established! to " + GAIUS_ADDRESS + " : " + GAIUS_PORT);
				
				if(this.GAIUS_MAINTAIN_SOCKET_CONNECTION)
					list_gaius_connections.add(this);
				
				//try to resolve self if needed
				if(driver.my_external_ip_address != null && !driver.my_external_ip_address.trim().equals("") && driver.GEO_LOCATION_ME != null && driver.GEO_LOCATION_ME.latitude != null && (driver.GEO_LOCATION_ME.latitude.trim().equals("") || driver.GEO_LOCATION_ME.latitude.trim().equals("")))
				{
					send_gaius(driver.my_external_ip_address);
					
					//try to resolve self GEO
					line = brIn_Gaius.readLine();
					
					if(line != null && line.toLowerCase().startsWith("successfully connected to "))//very good, we have received the acknowledgement, read again for the text we're looking for
						line = brIn_Gaius.readLine();
															
					if(line != null && !line.contains(driver.NO_RESULTS))
					{
						driver.GEO_LOCATION_ME.process_line(line);	
						driver.directive("If successful, my geo location has been updated to: " + driver.GEO_LOCATION_ME.get_data(", "));
					}					
				}
				
				//
				//infinite wait and process anything we receive
				//				
				while(continue_run && (line = this.brIn_Gaius.readLine()) != null)
				{
					line = line.trim();
					
					if(line.equals(""))
						continue;
					
					if(line.contains(",") || line.contains("{") || line.contains(" ") || line.contains(":") || line.contains("\""))
					{
						GEO_Location geo = new GEO_Location(line, false);
					}
				}
				
				

			}
			
			try	{	this.brIn_Gaius.close();} catch(Exception e){}
			
			if(list_gaius_connections != null && list_gaius_connections.contains(this))
			{
				try
				{
					list_gaius_connections.remove(this);
				}catch(Exception e){}
			}
			
			return true;
		}
		catch(ConnectException ce)
		{
			driver.directive("PUNT! I am unable to connect to [" + GAIUS_ADDRESS + "]. Did you type in the port correctly? --> Error Message: " + ce.getLocalizedMessage());
		}
		catch(SocketException se)
		{
			driver.directive("PUNT! I am unable to connect to [" + GAIUS_ADDRESS + "] It appears this IP address is incorrect or unreachable. Error Message: " + se.getLocalizedMessage());
		}
		catch(Exception e)
		{
			//driver.eop(myClassName, "establish_socket_to_gaius", e);
			driver.directive("\nCONNECTION ERROR! I was unable to connect to [" + GAIUS_ADDRESS + "] Error msg --> " + e.getLocalizedMessage());
		}
		
		return false;
	}
	
	public boolean send_gaius(String out)
	{
		try
		{
			if(this.pwOut_Gaius != null)
			{
				pwOut_Gaius.println(out);
				pwOut_Gaius.flush();
			}
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "send_gaius", e);
		}
		
		return false;
	}
	
	public static String connect_to_gaius(String value)
	{
		try
		{	
			String GAIUS_ADDRESS = null;
			int GAIUS_PORT = -1;
			
			if(value == null || value.trim().equals(""))
				value = driver.jop_Query("Please enter address to Gaius instance:", "Specify Gaius Address");
			
			if(value == null || value.trim().equals(""))
			{
				driver.directive("Specify Address to Gaius instance canceled");
				return null;
			}
			
			if(value.contains("localhost"))
				value = value.replaceAll("localhost", "127.0.0.1");
				
			value = value.trim();
									
			String addr = "";
			String port = "";
			int PORT = 80;
			
			String array [] = new String []{value};
			
			if(value.contains(","))
				array = value.split(",");
			else if(value.contains(" "))
				array = value.split(" ");			
			else if(value.contains(":"))
			{
				array = value.split(":");
				
				//ipv6 would have more than http://sldsjfldjf:80
				if(array != null && array.length > 2)
				{
					//assume ipv6 so set, back to the original address and hope address and port are specified using space or comma					
					array = new String[]{value};
				}				
			}
			
			//bifurcate address from port
			if(array == null || array.length < 1)
			{
				driver.directive("PUNT! Address does not appear to be valid [" + value + "]");
				addr = value;
				PORT = -1;
				
				GAIUS_ADDRESS = value;
				GAIUS_PORT = -1;
			}
			else if(array.length == 1)
			{
				GAIUS_ADDRESS = value;
				GAIUS_PORT = -1;
			}
			else
			{
				try
				{
					GAIUS_PORT = Integer.parseInt(array[array.length-1].trim()); 
					
					GAIUS_ADDRESS = array[0].trim();
					
					for(int i = 1; i < array.length-1; i++)
					{
						if(array[i].trim().equals(""))
							continue;
						
						GAIUS_ADDRESS = GAIUS_ADDRESS + ":" + array[i].trim();												
					}
				}
				catch(Exception ee)
				{
					driver.directive("PUNT!!! It appears Port number [" + array[array.length-1] + "] was invalid or missing! Please provide via <IP Address> <PORT>");
					return null;
				}
			}
				
			GLOBAL_GAIUS_CONNECTION_ADDRESS = GAIUS_ADDRESS;
			GLOBAL_GAIUS_CONNECTION_PORT = GAIUS_PORT;
			
			//attempt to connect!
			GEO_Location geo_gaius_instance = new GEO_Location(GAIUS_ADDRESS, GAIUS_PORT, true, true);
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "connect_to_gaius", e);
		}
		
		return null;
	}
	
	
	
	
	
	
	public static String set_gaius_address(String value)
	{
		try
		{	
			String GAIUS_ADDRESS = null;
			int GAIUS_PORT = -1;
			
			if(value == null || value.trim().equals(""))
				value = driver.jop_Query("Please enter address to Gaius instance:", "Specify Gaius Address [EPHEMERAL PORT]");
			
			if(value == null || value.trim().equals(""))
			{
				driver.directive("Specify Address to Gaius instance canceled");
				return null;
			}
			
			if(value.contains("localhost"))
				value = value.replaceAll("localhost", "127.0.0.1");
			
			value = value.trim();
			
			String addr = "";
			String port = "";
			int PORT = 80;
			
			String array [] = new String []{value};
			
			if(value.contains(" "))
				array = value.split(" ");
			else if(value.contains(","))
				array = value.split(",");
			else if(value.contains(":"))
			{
				array = value.split(":");
				
				//ipv6 would have more than http://sldsjfldjf:80
				if(array != null && array.length > 2)
				{
					//assume ipv6 so set, back to the original address and hope address and port are specified using space or comma					
					array = new String[]{value};
				}				
			}
			
			//bifurcate address from port
			if(array == null || array.length < 1)
			{
				driver.directive("PUNT! Address does not appear to be valid [" + value + "]");
				addr = value;
				PORT = -1;
				
				GAIUS_ADDRESS = value;
				GAIUS_PORT = -1;
			}
			else if(array.length == 1)
			{
				GAIUS_ADDRESS = value;
				GAIUS_PORT = -1;
			}
			else
			{
				try
				{
					GAIUS_PORT = Integer.parseInt(array[array.length-1].trim()); 
					
					GAIUS_ADDRESS = array[0].trim();
					
					for(int i = 1; i < array.length-1; i++)
					{
						if(array[i].trim().equals(""))
							continue;
						
						GAIUS_ADDRESS = GAIUS_ADDRESS + ":" + array[i].trim();												
					}
				}
				catch(Exception ee)
				{
					driver.directive("* PUNT!!! It appears Port number [" + array[array.length-1] + "] was invalid or missing! Please provide via <IP Address> <PORT>");
					return null;
				}
			}
			
			GLOBAL_GAIUS_CONNECTION_ADDRESS = GAIUS_ADDRESS;
			GLOBAL_GAIUS_CONNECTION_PORT = GAIUS_PORT;
			
			if(GAIUS_PORT > -1)
				driver.directive("\nGaius Address is set to [" + GAIUS_ADDRESS + "]  PORT [" + GAIUS_PORT + "]\n");
			else
				driver.directive("\nGaius Address is set to [" + GAIUS_ADDRESS + "].\n");
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "set_gaius_address", e);
		}
		
		return null;
	}
	
	public boolean import_file(File fle)
	{
		try
		{
			if(fle == null || !fle.exists() || !fle.isFile())
			{
				fle = driver.querySelectFile(true, "Please select GEO file to import...", JFileChooser.FILES_AND_DIRECTORIES, false, false);
				
				this.fleImport = fle;
			}
			
			//check if we have valid file
			if(fle == null || !fle.exists())
			{								
				driver.directive("Punt! No valid file selected. Import GEO subroutine not started");
				return false;
			}
			
			if(fle.isDirectory())
			{
				//otherwise file exists, start timer
				driver.directive("\nAttempting to open GEO import directory -->" + fle.getCanonicalPath());
				
				LinkedList<File> list_file = new LinkedList<File>();
				
				driver.getFileListing(fle, true, null, list_file);
				
				if(list_file == null || list_file.isEmpty())
				{
					driver.directive("PUNT! I am unable to import GEO entries.  No files were returned under directory --> " + fle.getCanonicalPath());
					return false;
				}
				
				for(File fle_to_import : list_file)
				{
					if(fle_to_import == null || !fle_to_import.exists() || !fle_to_import.isFile())
						continue;
					
					//Create a new thread to import... I'll see if I have to fix this later...
					GEO_Location geo = new GEO_Location(true, fle_to_import);					
				}
				
				
			}
			else
			{
				//otherwise file exists, start timer
				driver.directive("\nAttempting to open GEO import file -->" + fle.getCanonicalPath());
				
				brImportFile = new BufferedReader(new FileReader(fle));
				
				StandardInListener.stop = false;
				
				this.tmr_import = new javax.swing.Timer(30, this);
				tmr_import.start();
			}
			
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "import_file", e);
		}
		
		return false;
	}
	
	public void actionPerformed(ActionEvent ae)
	{
		try
		{
			if(ae.getSource() == tmr_update_resolutions && process_geo_lookup && AUTOMATIC_GEO_RESOLUTION_ENABLED)
			{
				update_geo_resolution();
			}
			
			else if(ae.getSource() == tmr_import)
			{
				process_interrupt_read_file();
			}
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "ae", e);
		}
	}
	
	public boolean process_interrupt_read_file()
	{
		try
		{
			if(!this.handle_interrupt_read_file)
				return false;
			
			handle_interrupt_read_file = false;
			
			this.line_import = this.brImportFile.readLine();
			
			//check if we're finished reading file
			if(this.line_import == null)
			{
					try	{	this.tmr_import.stop();	} catch(Exception e){}
					
					driver.directive("Complete! Num lines read: [" + this.num_lines_read + "] on file -->" + this.fleImport);
					
					try	{	this.brImportFile.close();	}	catch(Exception e){}
					
					//hold lock on semaphone
					return true;
			}
			
			if(StandardInListener.stop)
			{
				
				try	{	this.tmr_import.stop();	} catch(Exception e){}

				driver.directive("STOP RECEIVED! Num lines read: [" + this.num_lines_read + "]. Halting remaining import on file -->" + this.fleImport);

				try	{	this.brImportFile.close();	}	catch(Exception e){}

				//hold lock on semaphone
				return true;
			}
				
			
			if(num_lines_read % 100 == 0)
				driver.sp(".");
			
			++this.num_lines_read;
			
			//
			//otw, process the line
			//
			
			lower = line_import.toLowerCase().trim();
			
			//check for blank line
			if(lower.equals(""))
			{
				handle_interrupt_read_file = true;
				return true;
			}
			
			//check if line meets requirements
			if(lower.contains("latitude") && lower.contains("longitude"))
			{
				//process a new line request
				GEO_Location geo = new GEO_Location(line_import, true);
			}
			
					
			
			handle_interrupt_read_file = true;
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "process_interrupt_read_file", e);
		}
		
		handle_interrupt_read_file = true;
		return false;
	}
	
	public boolean process_line(String line)
	{
		try
		{
			if(line == null)
				return false;
			
			line = line.replaceAll("\"", "").trim();
			
			if(line.equals(""))
				return false;
			
			if(line.toLowerCase().contains(driver.NO_RESULTS))
				return false;
			
			if(line.toLowerCase().contains("successfully connected to "))
				return false; 
			
			line = line.replaceAll("\\{", "");
			line = line.replaceAll("\\}", "");

			String [] array = line.split(",");
			
			if(array == null || array.length < 1)
				return false;
			
			if(array.length < 2)
				array = line.split("\t");
			
			if(array == null || array.length < 1)
				return false;
			
			String lower = "";
			int i = 0;
			for(String tuple : array)
			{
				tuple = tuple.trim();				
				
				if(tuple.equals(""))
					continue;
				
				lower = tuple.toLowerCase().trim();
				
				if(lower.startsWith("ip"))
				{
					this.ip = tuple.substring(3).trim();
					this.array[0] = ip;
					
					if(address == null || address.trim().equals(""))
						address = ip;
					
				}
				
				else if(lower.startsWith("query"))
				{
					this.ip = tuple.substring(6).trim();
					this.array[0] = ip;
					
					if(address == null || address.trim().equals(""))
						address = ip;
					
				}
				
				else if(lower.startsWith("request"))
				{
					this.ip = tuple.substring(8).trim();
					this.array[0] = ip;
					
					if(address == null || address.trim().equals(""))
						address = ip;
					
				}
				
				else if(lower.startsWith("as"))
				{
					this.autonomous_system_name = tuple.substring(3).trim();
					//this.array[2] = country_code;
				}
				
				else if(lower.startsWith("isp"))
				{
					this.internet_service_provider = tuple.substring(4).trim();
					//this.array[2] = country_code;
				}
				
				else if(lower.startsWith("org"))
				{
					this.org = tuple.substring(4).trim();
					//this.array[2] = country_code;
				}
				
				else if(lower.startsWith("network:"))
				{
					this.network = tuple.substring("network:".length()).trim();
					//this.array[2] = country_code;
				}
				
				else if(lower.startsWith("continent_code:"))
				{
					this.continent_code = tuple.substring("continent_code:".length()).trim();
					//this.array[2] = country_code;
				}
				
				else if(lower.startsWith("continent_name:"))
				{
					this.continent_name = tuple.substring("continent_name:".length()).trim();
					//this.array[2] = country_code;
				}
				
				else if(lower.startsWith("geo_ip"))
				{
					this.ip = tuple.substring(7).trim();
					this.array[0] = ip;
					
					if(address == null || address.trim().equals(""))
						address = ip;
					
				}
				
				else if(lower.startsWith("country_code"))
				{
					this.country_code = tuple.substring(13).trim();
					this.array[2] = country_code;
				}
												
				else if(lower.startsWith("countrycode"))
				{
					this.country_code = tuple.substring(12).trim();
					this.array[2] = country_code;
				}
				
				else if(lower.startsWith("geo_country_code"))
				{
					this.country_code = tuple.substring(17).trim();
					this.array[2] = country_code;
				}
				
				else if(lower.startsWith("country_name"))
				{
					this.country_name = tuple.substring(13).trim();
					this.array[3] = country_name;
				}
				
				else if(lower.startsWith("country:"))
				{
					this.country_name = tuple.substring(8).trim();
					this.array[3] = country_name;
				}
				
				else if(lower.startsWith("geo_country_name"))
				{
					this.country_name = tuple.substring(17).trim();
					this.array[3] = country_name;
				}
				
				else if(lower.startsWith("region_code"))
				{
					this.region_code = tuple.substring(12).trim();
					this.array[4] = region_code;
				}
				
				else if(lower.startsWith("region_state_code:"))
				{
					this.region_code = tuple.substring("region_state_code:".length()).trim();
					this.array[4] = region_code;
				}
				
				else if(lower.startsWith("region:"))
				{
					this.region_code = tuple.substring(7).trim();
					this.array[4] = region_code;
				}
				
				else if(lower.startsWith("geo_region_code"))
				{
					this.region_code = tuple.substring(16).trim();
					this.array[4] = region_code;
				}
				
				else if(lower.startsWith("region_name"))
				{
					this.region_name = tuple.substring(12).trim();
					this.array[5] = region_name;
				}
				
				else if(lower.startsWith("region_state_name:"))
				{
					this.region_name = tuple.substring("region_state_name:".length()).trim();
					this.array[5] = country_code;
				}
				
				else if(lower.startsWith("regionname"))
				{
					this.region_name = tuple.substring(11).trim();
					this.array[5] = region_name;
				}
				
				else if(lower.startsWith("geo_region_name"))
				{
					this.region_name = tuple.substring(16).trim();
					this.array[5] = region_name;
				}
				
				else if(lower.startsWith("city_name:"))
				{
					this.city = tuple.substring("city_name:".length()).trim();
					this.array[6] = city;
				}
				
				else if(lower.startsWith("city"))
				{
					this.city = tuple.substring(5).trim();
					this.array[6] = city;
				}
				
				else if(lower.startsWith("geo_city"))
				{
					this.city = tuple.substring(9).trim();
					this.array[6] = city;
				}
				
				else if(lower.startsWith("zip_code"))
				{
					this.zip_code = tuple.substring(9).trim();
					this.array[7] = zip_code;
				}
				
				else if(lower.startsWith("postal_code"))
				{
					this.zip_code = tuple.substring(12).trim();
					this.array[7] = zip_code;
				}
				
				else if(lower.startsWith("postalcode"))
				{
					this.zip_code = tuple.substring(11).trim();
					this.array[7] = zip_code;
				}
				
				else if(lower.startsWith("zip:"))
				{
					this.zip_code = tuple.substring(4).trim();
					this.array[7] = zip_code;
				}
				
				else if(lower.startsWith("geo_zip_code"))
				{
					this.zip_code = tuple.substring(13).trim();
					this.array[7] = zip_code;
				}
				
				else if(lower.startsWith("time_zone"))
				{
					this.time_zone = tuple.substring(10).trim();
					this.array[8] = time_zone;
				}
				
				else if(lower.startsWith("timezone"))
				{
					this.time_zone = tuple.substring(9).trim();
					this.array[8] = time_zone;
				}
				
				else if(lower.startsWith("geo_time_zone"))
				{
					this.time_zone = tuple.substring(14).trim();
					this.array[8] = time_zone;
				}
				
				else if(lower.startsWith("latitude"))
				{
					this.latitude = tuple.substring(9).trim();
					this.array[9] = latitude;
					this.array[1] = latitude;
				}
				
				else if(lower.startsWith("lat"))
				{
					this.latitude = tuple.substring(4).trim();
					this.array[9] = latitude;
					this.array[1] = latitude;
				}
				
				else if(lower.startsWith("geo_latitude"))
				{
					this.latitude = tuple.substring(13).trim();
					this.array[9] = latitude;
					this.array[1] = latitude;
				}
				
				else if(lower.startsWith("longitude"))
				{
					this.longitude = tuple.substring(10).trim();
					this.array[10] = longitude;
					this.array[1] = latitude + ", " + longitude;
				}
				
				else if(lower.startsWith("lon"))
				{
					this.longitude = tuple.substring(4).trim();
					this.array[10] = longitude;
					this.array[1] = latitude + ", " + longitude;
				}
				
				else if(lower.startsWith("geo_longitude"))
				{
					this.longitude = tuple.substring(14).trim();
					this.array[10] = longitude;
					this.array[1] = latitude + ", " + longitude;
				}
				
				else if(lower.startsWith("metro_code"))
				{
					this.metro_code = tuple.substring(11).trim();		
					this.array[11] = metro_code;
				}
				
				else if(lower.startsWith("metro_area_code:"))
				{
					this.metro_code = tuple.substring("metro_area_code:".length()).trim();		
					this.array[11] = metro_code;
				}
				
				else if(lower.startsWith("geo_metro_code"))
				{
					this.metro_code = tuple.substring(15).trim();		
					this.array[11] = metro_code;
				}
				
				else if(!SURPRESS_ERROR_MESSAGES)
					driver.sop("UNKNOWN TUPLE VALUE received in " + myClassName + ". Tuple [" + tuple + "]. full json: " + line + ". index: " + i);
				
				++i;
			}
			
			
			//ip:23.52.32.93,country_code:NL,country_name:Netherlands,region_code:NH,region_name:North Holland,city:Amsterdam,zip_code:1091,time_zone:Europe/Amsterdam,latitude:52.35,longitude:4.9167,metro_code:0

			/*driver.directive("ip-->" + ip + "<--");
			driver.directive("country_code-->" + country_code + "<--");
			driver.directive("country_name-->" + country_name + "<--");
			driver.directive("region_code-->" +region_code  + "<--");
			driver.directive("region_name-->" +  region_name+ "<--");
			driver.directive("city-->" + city + "<--");
			driver.directive("zip_code-->" + zip_code + "<--");
			driver.directive("time_zone-->" + time_zone + "<--");
			driver.directive("latitude-->" + latitude + "<--");
			driver.directive("longitude-->" + longitude + "<--");
			driver.directive("metro_code-->" + metro_code + "<--");*/
			
			//here, validate lat and lon, if so, store
			try
			{
				Double.parseDouble(this.latitude);
				Double.parseDouble(this.longitude);
				
				//
				//LINK
				//
				if(!TREE_GEO_LOCATION.containsKey(address))
				{
					TREE_GEO_LOCATION.put(address,  this);					
					log_geo(", \t");
					update_required = true;
					
					resolution_complete = true;
				}
				
			}
			catch(Exception e)
			{
				TREE_NOT_FOUND.put(address,  this);
				log_not_found(address);
			}
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "process_line", e);
		}
		
		return false;
	}
	
	
	public boolean log_geo(String delimiter)
	{
		try
		{
			//
			//log dns resolution
			//
			if(this.log_geo == null)
			{
				log_geo = new Log("geo/geo_found/",  "geo_found", 250, 999999999);
				log_geo.OVERRIDE_LOGGING_ENABLED = true;
			}
			
			log_geo.log_directly(
									"ip: " + ip + delimiter + 
									"country_code: " + country_code + delimiter + 
									"country_name: "  + country_name + delimiter + 
									"region_code: "  + region_code + delimiter + 
									"region_name: "  + region_name + delimiter + 
									"city: "  + city + delimiter + 
									"zip_code: "  + zip_code + delimiter + 
									"time_zone: "  + time_zone + delimiter + 
									"latitude: "  + latitude + delimiter + 
									"longitude: "  + longitude + delimiter + 
									"metro_code: "  + metro_code);
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "log_geo", e);
		}
		
		return false;
	}
	
	public String get_data(String delimiter)
	{
		try
		{
			
							return	"ip: " + ip + delimiter + 
									"country_code: " + country_code + delimiter + 
									"country_name: "  + country_name + delimiter + 
									"region_code: "  + region_code + delimiter + 
									"region_name: "  + region_name + delimiter + 
									"city: "  + city + delimiter + 
									"zip_code: "  + zip_code + delimiter + 
									"time_zone: "  + time_zone + delimiter + 
									"latitude: "  + latitude + delimiter + 
									"longitude: "  + longitude + delimiter + 
									"metro_code: "  + metro_code;
			
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "get_data", e);
		}
		
		return " ++ ";
	}
	
	public String toString(String delimiter)
	{
		try
		{
			delimiter = delimiter + " ";
			
			geo_string = "";
			
			if(ip != null && !ip.trim().equals(""))
				geo_string = " geo_ip: " + ip + delimiter;
			
			if(country_code != null && !country_code.trim().equals(""))
				geo_string = geo_string +  "geo_country_code: " + country_code + delimiter ;
			
			if(country_name != null && !country_name.trim().equals(""))
				geo_string = geo_string +  "geo_country_name: "  + country_name + delimiter ; 
			
			if(region_code != null && !region_code.trim().equals(""))
				geo_string = geo_string +  "geo_region_code: "  + region_code + delimiter ; 
			
			if(region_name != null && !region_name.trim().equals(""))
				geo_string = geo_string +  "geo_region_name: "  + region_name + delimiter ;
			
			if(city != null && !city.trim().equals(""))
				geo_string = geo_string +  "geo_city: "  + city + delimiter ; 
			
			if(zip_code != null && !zip_code.trim().equals(""))
				geo_string = geo_string +  "geo_zip_code: "  + zip_code + delimiter ; 
			
			if(time_zone != null && !time_zone.trim().equals(""))
				geo_string = geo_string +  "geo_time_zone: "  + time_zone + delimiter ; 
			
			if(latitude != null && !latitude.trim().equals(""))
				geo_string = geo_string +  "geo_latitude: "  + latitude + delimiter ; 
			
			if(longitude != null && !longitude.trim().equals(""))
				geo_string = geo_string +  "geo_longitude: "  + longitude + delimiter ;
			
			if(metro_code != null && !metro_code.trim().equals(""))
				geo_string = geo_string +  "geo_metro_code: "  + metro_code;
			
			
			return geo_string;
			
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "toString", e);
		}
		
		return " ++ ";
	}
	
	
	
	public String get_map_details()
	{
		try
		{
			map_details = "";
			
			if(ip != null && !ip.trim().equals(""))
				map_details = map_details + "<b>geo_ip</b>: " + ip+ "<br>";
			
			if(country_code != null && !country_code.trim().equals(""))
				map_details = map_details +  "<b>geo_country_code</b>: " + country_code+ "<br>";
			
			if(country_name != null && !country_name.trim().equals(""))
				map_details = map_details +  "<b>geo_country_name</b>: "  + country_name+ "<br>"; 
			
			if(region_code != null && !region_code.trim().equals(""))
				map_details = map_details +  "<b>geo_region_code</b>: "  + region_code+ "<br>"; 
			
			if(region_name != null && !region_name.trim().equals(""))
				map_details = map_details +  "<b>geo_region_nam</b>e: "  + region_name+ "<br>";
			
			if(city != null && !city.trim().equals(""))
				map_details = map_details +  "<b>geo_city</b>: "  + city+ "<br>"; 
			
			if(zip_code != null && !zip_code.trim().equals(""))
				map_details = map_details +  "<b>geo_zip_code</b>: "  + zip_code+ "<br>"; 
			
			if(time_zone != null && !time_zone.trim().equals(""))
				map_details = map_details +  "<b>geo_time_zone</b>: "  + time_zone+ "<br>"; 
			
			if(latitude != null && !latitude.trim().equals(""))
				map_details = map_details +  "<b>geo_latitude</b>: "  + latitude+ "<br>"; 
			
			if(longitude != null && !longitude.trim().equals(""))
				map_details = map_details +  "<b>geo_longitude</b>: "  + longitude+ "<br>";
			
			if(metro_code != null && !metro_code.trim().equals(""))
				map_details = map_details +  "<b>geo_metro_code</b>: "  + metro_code+ "<br>";
			
			
			return map_details.replaceAll("'", "");
			
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "get_map_details", e);
		}
		
		return "  ";
	}
	
	public boolean log_not_found(String address)
	{
		try
		{
			//
			//log dns resolution
			//
			if(this.log_not_found == null)
			{
				log_not_found = new Log("geo/geo_not_found/",  "geo_not_found", 250, 999999999);
				log_not_found.OVERRIDE_LOGGING_ENABLED = true;
			}
			
			log_not_found.log_directly(address);
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "log_not_found", e);
		}
		
		return false;
	}
	
	public boolean is_private_non_routable_ip(String ip)
	{
		try
		{
			if(ip == null)
				return true;
			
			ip = ip.trim();
			
			if(ip.equals(""))
				return true;
			
			if(ip.startsWith("239.255.255"))
				return true;
			
			int octet_1 = 0;
			int octet_2 = 0;
			int octet_3 = 0;
			int octet_4 = 0;
						
			try
			{
				String [] array_ip = ip.split("\\.");
				octet_1 = Integer.parseInt(array_ip[0].trim());
				octet_2 = Integer.parseInt(array_ip[1].trim());								
				octet_3 = Integer.parseInt(array_ip[2].trim());
				octet_4 = Integer.parseInt(array_ip[3].trim());
			}
			catch(Exception e)
			{
				return false;
			}
			
			if(octet_1 == 172)
			{
				if(octet_2 >= 16 && octet_2 <= 31)
					return true;
			}
			
			if(octet_1 == 192 && octet_2 == 168)
				return true;
			
			//0.0.0.0/8
			if(ip.startsWith("0."))
				return true;
			
			
			
			//10.0.0.0/8
			if(ip.startsWith("10."))
				return true;
								
			
			//127.0.0.0/8
			if(ip.startsWith("127."))
				return true;									
			
			//169.254.0.0/16
			if(ip.startsWith("169.254."))
				return true;
											
			//192.0.0.0/24
			if(ip.startsWith("192.0.0."))
				return true;
									
			
			//192.88.99.0/24
			if(ip.startsWith("192.88.99."))
				return true;
									
			
			//192.168.0.0/16
			if(ip.startsWith("192.168."))
				return true;
						
						
			
			//198.18.0.0/15
			if(ip.startsWith("198.18."))
				return true;
			
			
			//198.19.255.255
			if(ip.startsWith("198.19."))
				return true;
			
			
			//198.51.100.0/24
			if(ip.startsWith("198.51.100."))
				return true;
									
			
			//203.0.113.0/24
			if(ip.startsWith("203.0.113."))
				return true;
			
			//224.0.0.0/4
			if(ip.startsWith("224."))
				return true;			
			
			//240.0.0.0/4
			if(ip.startsWith("240."))
				return true;			
			
			
			//255.255.255.255
			if(ip.equals("255.255.255.255"))
				return true;	
			
								
			
			
			/*//::1/128
			if(ip.startsWith(""))
				return true;
			
			
			//::ffff:0:0/96
			if(ip.startsWith(""))
				return true;
			
			
			//::ffff:255.255.255.255
			if(ip.startsWith(""))
				return true;
			
			
			//64:ff9b::/96
			if(ip.startsWith(""))
				return true;
			
			
			//64:ff9b::255.255.255.255
			if(ip.startsWith(""))
				return true;
			
			
			//100::/64
			if(ip.startsWith(""))
				return true;
			
			
			//100::ffff:ffff:ffff:ffff
			if(ip.startsWith(""))
				return true;
			
			
			//2001::/32
			if(ip.startsWith(""))
				return true;
			
			
			//2001::ffff:ffff:ffff:ffff:ffff:ffff
			if(ip.startsWith(""))
				return true;
			
			
			//2001:10::/28
			if(ip.startsWith(""))
				return true;
			
			
			//2001:1f:ffff:ffff:ffff:ffff:ffff:ffff
			if(ip.startsWith(""))
				return true;
			
			
			//2001:20::/28
			if(ip.startsWith(""))
				return true;
			
			
			//2001:2f:ffff:ffff:ffff:ffff:ffff:ffff
			if(ip.startsWith(""))
				return true;
			
			
			//2001:db8::/32
			if(ip.startsWith(""))
				return true;
			
			
			//2001:db8:ffff:ffff:ffff:ffff:ffff:ffff
			if(ip.startsWith(""))
				return true;
			
			
			//2002::/16
			if(ip.startsWith(""))
				return true;
			
			
			//2002:ffff:ffff:ffff:ffff:ffff:ffff:ffff
			if(ip.startsWith(""))
				return true;
			
			
			//fc00::/7
			if(ip.startsWith(""))
				return true;
			
			
			//fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff
			if(ip.startsWith(""))
				return true;
									
			
			//febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff
			if(ip.startsWith("febf"))
				return true;
			
			
			//ff00::/8
			if(ip.startsWith("ff00"))
				return true;*/
			
			

			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "is_private_non_routable_ip", e);
		}
		
		return false;
	}
	
	
//	public void resolve_self()
//	{
//		try
//		{
//			//good reference: https://stackoverflow.com/questions/2793150/how-to-use-java-net-urlconnection-to-fire-and-handle-http-requests, https://stackoverflow.com/questions/3163693/java-urlconnection-timeout
//			
//			//address was not found, attempt to resolve now!
//			driver.sop("Attempting to resolve external GEO information...");
//			
//			URL url = new URL(QUERY_ADDRESS + address);
//			address = "me";
//			HttpURLConnection connection = (HttpURLConnection) url.openConnection();
//			HttpURLConnection.setFollowRedirects(true);
//			connection.setConnectTimeout(20 * 1000);
//			connection.setRequestMethod("GET");
//			connection.setRequestProperty("User-Agent", "Mozilla/5.0 (Windows; U; Windows NT 6.0; en-US; rv:1.9.1.2) Gecko/20180719 chrome/64.0.3282.140 (.NET CLR 3.5.30729)");
//			connection.connect();
//			
//			BufferedReader brIn = new BufferedReader(new InputStreamReader(connection.getInputStream()));
//			
//			String line = "";
//			
//			while((line = brIn.readLine()) != null)
//			{
//				line = line.trim();
//				
//				if(line.trim().equals(""))
//					continue;
//				
//				process_line(line);
//			}
//			
//			try	{	brIn.close();} catch(Exception e){}
//			
//			driver.sop("If successful, our Geo information was found to be: " + get_data(", "));
//			
//			
//			
//			origin_latitude = latitude;
//			origin_longitude = longitude;
//									
//			System.gc();
//		}
//		
//		
//		catch(FileNotFoundException fnef)
//		{
//			driver.directive("\nNOTE! I CAN NOT RESOLVE OUR EXTERNAL IP");							
//		}
//		
//		catch(UnknownHostException uhe)
//		{
//			driver.directive("\nNOTE!!! I CAN NOT RESOLVE OUR EXTERNAL IP");							
//		}
//		
//		catch(Exception e)
//		{						
//			driver.eop(myClassName, "resolve_self", e);
//		}
//	}
	
	/**
	 * First time, set resolution_count == 0;
	 * @param resolution_count
	 * @return
	 */
	public String resolve_self(int resolution_count)
	{
		String query_address = external_ip_address_resolution_server_address_0;
		
		try
		{
			//good reference: https://stackoverflow.com/questions/2793150/how-to-use-java-net-urlconnection-to-fire-and-handle-http-requests, https://stackoverflow.com/questions/3163693/java-urlconnection-timeout

			//address was not found, attempt to resolve now!
			driver.sop("Attempting to resolve external IP information. Resolution count[" + resolution_count + "]...");
			
			if(resolution_count < 0)
				resolution_count = 0;
			
			if(resolution_count > 2)
			{
				driver.directive("PUNT! I could not determine my self IP address.");
				return "";
			}				
			
			
			
			switch(resolution_count++)
			{
				case 0:
				{
					query_address = external_ip_address_resolution_server_address_0;
					break;
				}
				case 1:
				{
					query_address = external_ip_address_resolution_server_address_1;
					break;
				}
				case 2:
				{
					query_address = external_ip_address_resolution_server_address_2;
					break;
				}
				default:
				{
					driver.directive("NOTE: I COULD NOT DETERMINE RESOLUTION_COUNT CASE in "+ myClassName + ". I am defaulting to " + query_address);
					break;
				}
			}
			
			URL url = new URL(query_address);
			HttpURLConnection connection = (HttpURLConnection) url.openConnection();
			HttpURLConnection.setFollowRedirects(true);
			connection.setConnectTimeout(20 * 1000);
			connection.setRequestMethod("GET");			
			connection.setRequestProperty("User-Agent", "Mozilla/5.0 (Windows; U; Windows NT 6.0; en-US; rv:1.9.1.2) Gecko/20180719 chrome/4.0.3282.140 (.NET CLR 3.5.30729)");
			connection.connect();

			BufferedReader brIn = new BufferedReader(new InputStreamReader(connection.getInputStream()));

			String line = "";

			address = "";
			
			while((line = brIn.readLine()) != null)
			{
				line = line.trim();

				if(line.trim().equals(""))
					continue;

				if(line.contains("{"))
				{
					this.process_line(line);					
				}
				else
				{
					//hopefully the only line is the ip address external which remains in line :-)
					address = line;
				}
			}

			try	{	brIn.close();} catch(Exception e){}
			
			if(address == null || (address.contains("html") && address.contains("meta http")))
				address = "";
			
		
			else if(address == null || address.trim().equals(""))
			{
				//driver.sop("Nope! I was not able to determine my external IP address...");
				return resolve_self(resolution_count);
			}
			else			
			{
				//10.15.238.191, 212.83.130.210
				if(address != null && address.contains(","))
				{
					String array [] = address.split(",");
					
					for(String val : array)
					{
						if(val == null || val.trim().equals(""))
							continue;
						
						address = val;
						break;
					}
				}
				
				//213.174.123.194
				//{"as":"AS29283 Hub One SA","city":"Roissy-en-France (Hyatt Regency Paris - Charles de Gaulle)","country":"France","countryCode":"FR","isp":"HUB TELECOM (formely ADP TELECOM)","lat":48.9908,"lon":2.51556,"org":"","query":"213.174.123.194","region":"IDF","regionName":"Île-de-France","status":"success","timezone":"Europe/Paris","zip":"95700"}
				//driver.directive("\n\n\n\n" + address);
				
				driver.sop("If successful, our external IP address information was found to be: " + address);
				
				driver.my_external_ip_address = address;
				
				if(this.latitude != null && !this.latitude.trim().equals(""))
				{
					origin_latitude = this.latitude;
					origin_latitude = this.longitude;
					
					driver.sop("Oh joy! Our Geo IP information was found to be: " + this.get_data(", "));
				}
			}
			
			try	{	brIn.close();} catch(Exception e){}
			
			//System.gc();
			
						
			return address;
		}


		catch(FileNotFoundException fnef)
		{
			driver.directive("\nNOTE! I CAN NOT RESOLVE OUR EXTERNAL IP");							
		}

		catch(UnknownHostException uhe)
		{
			//driver.directive("\n* NOTE!!! I CAN NOT RESOLVE OUR EXTERNAL IP from address [" + query_address + "]");							
			driver.directive("\n* NOTE!!! I CAN NOT RESOLVE OUR EXTERNAL IP from resolution [" + (resolution_count-1) + "]");
		}

		catch(Exception e)
		{						
			//driver.eop(myClassName, "resolve_self_ip", e);
			driver.directive("\nPUNT! Resoluion attempt failed: " + e.getLocalizedMessage());
		}
		
		return resolve_self(resolution_count);
	}
	
	
	
	
	public static boolean send_update_request(String addr)
	{
		try
		{
			if(addr == null)
				return false;
			
			addr = addr.trim();
			
			if(addr.equals(""))
				return false;
			
			boolean need_to_perform_resolution_in_separate_thread = false;
			
			//check if we have a dedicated line first
			if(list_gaius_connections != null && list_gaius_connections.size() > 0)
			{
				for(GEO_Location daemon : list_gaius_connections)
				{
					try
					{
						driver.sop("Requesting update from Gaius for address [" + addr + "]");
						daemon.send_gaius(addr);
						
						need_to_perform_resolution_in_separate_thread = false;
					}
					catch(Exception e)
					{
						if(list_gaius_connections != null && list_gaius_connections.contains(daemon))
						{
							try			{		list_gaius_connections.remove(daemon);	}catch(Exception ee){}
						}
						
						need_to_perform_resolution_in_separate_thread = true;
					}
				}
				
				if(need_to_perform_resolution_in_separate_thread)
				{
					GEO_Location geo = new GEO_Location(addr);
				}
			}
			else
			{
				//no dedicated geo sockets, use this one...
				GEO_Location geo = new GEO_Location(addr);
			}						
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "send_update_request", e);
		}
		
		return false;
	}
	
	
	
	public static boolean update_geo_resolution()
	{
		try
		{
			if(!process_geo_lookup)
				return false;			
						
			if(driver.GEO_LOCATION_ME == null)
			{
				driver.GEO_LOCATION_ME = new GEO_Location();				
			}
			else if(driver.GEO_LOCATION_ME != null && (driver.GEO_LOCATION_ME.latitude == null || driver.GEO_LOCATION_ME.latitude.trim().equals("")))
			{
				//check if we know the location of Gaius
				if(driver.my_external_ip_address != null && !driver.my_external_ip_address.trim().equals("") && GEO_Location.GLOBAL_GAIUS_CONNECTION_ADDRESS != null && !GEO_Location.GLOBAL_GAIUS_CONNECTION_ADDRESS.trim().equals(""))
				{
					driver.GEO_LOCATION_ME.address = driver.my_external_ip_address;
					driver.GEO_LOCATION_ME.perform_resolution();
				}
			}
			
			//lock semaphore
			process_geo_lookup = false;
			
			//
			//SOURCE
			//
			if(SOURCE.TREE_SOURCE_NODES != null && !SOURCE.TREE_SOURCE_NODES.isEmpty())
			{
				for(SOURCE src : SOURCE.TREE_SOURCE_NODES.values())
				{
					if(src == null)
						continue;
					
					if(src.geo != null)
						continue;
					
					if(src.is_private_non_routable_ip)
						continue;
					
					if(src.src_ip == null || src.src_ip.equals(""))
						continue;
					
					if(TREE_GEO_LOCATION.containsKey(src.src_ip))
					{
						src.geo = TREE_GEO_LOCATION.get(src.src_ip);
						continue;
					}
					
					
					if(TREE_ADDRESS_TO_LOOKUP.containsKey(src.src_ip))
						continue;
					
					else if(TREE_NOT_FOUND.containsKey(src.src_ip))
						continue;
					
					TREE_ADDRESS_TO_LOOKUP.put(src.src_ip, null);
						
					//otw, resolve!
					send_update_request(src.src_ip);
					
					//GEO_Location geo = new GEO_Location(src.src_ip);
				}
			}
			
			//
			//RESOURCE
			//
			if(Resolution.TREE_RESOURCE != null && !Resolution.TREE_RESOURCE.isEmpty())
			{
				for(Resolution rsrc : Resolution.TREE_RESOURCE.values())
				{
					if(rsrc == null)
						continue;
					
					if(rsrc.geo != null)
						continue;
					
					if(rsrc.is_private_non_routable_ip)
						continue;
					
					if(rsrc.address == null || rsrc.address.equals(""))
						continue;
					
					if(TREE_GEO_LOCATION.containsKey(rsrc.address))
					{
						rsrc.geo = TREE_GEO_LOCATION.get(rsrc.address);
						driver.sop("Geo Location for " + rsrc.address + " has been updated to [" + TREE_GEO_LOCATION.get(rsrc.address).get_data(", ") + "]");
						continue;
					}
					
					if(TREE_ADDRESS_TO_LOOKUP.containsKey(rsrc.address))
						continue;
					
					if(TREE_NOT_FOUND.containsKey(rsrc.address))
						continue;
					
					TREE_ADDRESS_TO_LOOKUP.put(rsrc.address, null);
					
					
					//otw, resolve!
					//GEO_Location geo = new GEO_Location(rsrc.address);
					send_update_request(rsrc.address);
				}
			}
			
			//
			//NETSTAT
			//
			if(Node_Netstat.tree_netstat != null && !Node_Netstat.tree_netstat.isEmpty())
			{
				for(Node_Netstat node : Node_Netstat.tree_netstat.values())
				{
					if(node == null)
						continue;
					
					if(node.geo != null)
						continue;
					
					//if(node.is_private_non_routable_ip)
					//	continue;
					
					if(node.foreign_address == null || node.foreign_address.equals(""))
						continue;
					
					if(TREE_GEO_LOCATION.containsKey(node.foreign_address))
					{
						node.geo = TREE_GEO_LOCATION.get(node.foreign_address);
						continue;
					}

					
					if(TREE_ADDRESS_TO_LOOKUP.containsKey(node.foreign_address))
						continue;
					
					if(TREE_NOT_FOUND.containsKey(node.foreign_address))
						continue;
					
					if(node.foreign_address.equalsIgnoreCase("*:*") || node.foreign_address.equalsIgnoreCase("0.0.0.0") || node.foreign_address.equalsIgnoreCase("[::]"))
						continue;
															
					TREE_ADDRESS_TO_LOOKUP.put(node.foreign_address, null);
					
					//otw, resolve!
					//GEO_Location geo = new GEO_Location(node.foreign_address);
					send_update_request(node.foreign_address);
				}
			}
			
			//
			//now send for TREE_ADDRESS_TO_LOOKUP
			//
			try	{	keys_to_remove.clear();   }	 catch(Exception e){keys_to_remove = new LinkedList<String>();}
			
			for(String address_to_lookup : TREE_ADDRESS_TO_LOOKUP.keySet())
			{
				if(address_to_lookup == null || address_to_lookup.trim().equals(""))
				{					
					keys_to_remove.add(address_to_lookup);
					continue;
				}
				
				address_to_lookup = address_to_lookup.trim();
				
				if(TREE_GEO_LOCATION.containsKey(address_to_lookup))
				{
					keys_to_remove.add(address_to_lookup);
					continue;
				}
				
				//otw, send request for new lookup!
				send_update_request(address_to_lookup);
			}
			
			//remove keys if necessary
			for(String key : keys_to_remove)
				try	{	TREE_ADDRESS_TO_LOOKUP.remove(key);} catch(Exception e){}
			
			
			process_geo_lookup = true;
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "update_geo_resolution", e);
		}
		
		
		process_geo_lookup = true;
		return false;
	}
	
	
	
	
	public static File export_geo(boolean print_table_header, String delimiter, boolean open_file_upon_completion, String file_name)
	{
		try
		{
			update_geo_resolution();
			
			if(GEO_Location.TREE_GEO_LOCATION== null || TREE_GEO_LOCATION.isEmpty())
			{
				if(open_file_upon_completion)
					driver.directive("PUNT! No GEO data has been populated yet. Consider running \"update_geo\" command...");
				
				return null;
			}
									
			//ensure parent file exists
			File top_folder = new File("." + File.separator + Driver.NAME);
			
			File export = new File("." + File.separator + Driver.NAME + File.separator + "export");
			
			if(!export.exists() || !export.isDirectory())
				export.mkdirs();			
									
			if(export == null || !export.exists() || !export.isDirectory())
				export = new File("./");
			
			String path = export.getCanonicalPath().trim();
			
			if(!path.endsWith(File.separator))
				path = path + File.separator;
			
			//create the stream
			File fle = new File(path + file_name);
			PrintWriter pwOut = new PrintWriter(new FileWriter(fle), true);
			
			//
			//print data
			//
			for(GEO_Location node : GEO_Location.TREE_GEO_LOCATION.values())					
			{
				if(node == null)
					continue;
				
				pwOut.println("\t" + node.toString(delimiter));
			}						
			
			
			
			pwOut.flush();
			pwOut.close();
			
						
			
			if(open_file_upon_completion && fle != null && fle.exists())
			{
				driver.open_file(fle);
			}
			
			
			
			return fle;	
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "export_geo", e);
		}
		
		return null;
	}
	
	
	public String [] get_jtable_row()
	{
		try
		{
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "get_jtable_row", e);
		}
		
		return array;
	}
	
	public boolean is_valid_ip_address(String address)
	{
		try
		{
			//here, check if we can convert it into a decimal. If so, then let's try the request
			address_decimal = convert_ipv4_to_decimal(address, true); 
						
			if(address_decimal < 0)
				return false;
			
			return true;
		}
		catch(Exception e)
		{
			//driver.eop(myClassName, "is_valid_ip_address", e);
		}
		
		return false;
	}
	
	public long convert_ipv4_to_decimal(String ip, boolean surpress_error_msg)
	{
		try
		{
			//special thanks to https://www.mkyong.com/java/java-convert-ip-address-to-decimal-number/
			
			String[] array = ip.split("\\.");
			
			if(array.length < 4)
				return -1;

			 result = 0;
			
			power = 3;
			ip_decimal = 0;
			
			for (int i = 0; i < array.length; i++) 
			{
				power = 3 - i;					
				ip_decimal = Integer.parseInt(array[i]);
				
				if(ip_decimal > 255 || ip_decimal < 0)
					return -1;
				
				result += ip_decimal * Math.pow(256, power);
				
				//result += ((Integer.parseInt(array[i])%256 * Math.pow(256,power)));
			}
			
			//could also visit --http://www.myteneo.net/blog/-/blogs/java-ip-address-to-integer-and-back/
			
			return result;
		}
		catch(Exception e)
		{
			if(!surpress_error_msg)
				driver.eop(myClassName, "convert_ipv4_to_decimal on request --> " + ip);
		}
		
		return -1;
	}
	
	
	
	
	
}
