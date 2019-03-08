/**
 * @author Solomon Sonya
 */


package Driver;

import java.io.*;
import java.net.Socket;
import java.util.LinkedList;

import javax.swing.JFileChooser;
import javax.swing.JOptionPane;

import GEO_Location.GEO_Location;
import OUI_Parser.*;
import Interface.Interface;
import Worker.*;
import nmap.NMap;
import Parser.*;
import Sensor.Sensor;
import Sensor.SensorServerSocket;
import Whois_IDS_ResolutionRequest.Whois_IDS_ResolutionRequest_ServerSocket;
import Whois_IDS_ResolutionRequest.Whois_IDS_ResolutionRequest_ThdSocket;


public class Start extends Thread implements Runnable
{
	public static final String myClassName = "Start";
	public static volatile Driver driver = new Driver();
	public static volatile StandardInListener std_in = new StandardInListener();
	public static volatile ThdWorker worker = new ThdWorker();
	
	public static boolean launch_gui = false;

	public static volatile String TSHARK_RUN_COMMAND = "tshark" ;
	public static final String SENSOR_PARAMETERS = "-T fields -e frame.time -e ip.proto -e eth.src -e ip.src -e tcp.srcport -e udp.srcport -e _ws.col.Protocol -e eth.dst -e ip.dst -e tcp.dstport -e udp.dstport -e dns.qry.name -e http.referer -e http.request.full_uri -e http.request -e http.cookie -e _ws.col.Info -e http.host -e http.user_agent";

	public volatile SensorServerSocket svrskt = null;
	public volatile ParserServerSocket svrskt_parser = null;
	
	public static volatile String arg = "";
	public static volatile String specific_interface = null;
	public static volatile int specific_SENSOR_port = SensorServerSocket.DEFAULT_PORT;
	public static volatile int specific_PARSER_port = ParserServerSocket.DEFAULT_PORT;
	
	public static volatile String encryption_key = null;
	public static volatile String sensor_name = Driver.NAME + "_" + System.currentTimeMillis();
	
	public static volatile boolean START_SENSOR = false;
	public static volatile boolean START_PARSER = false;
	public static volatile boolean START_BOTH_SENSOR_AND_PARSER = false;
	
	public static volatile LinkedList<String> list_interfaces = null;
	public static volatile boolean use_interface_number = true;
	public volatile Whois_IDS_ResolutionRequest_ServerSocket resolution_serversocket = null;
	
	public Start(String args [])
	{
		try
		{
			if(Driver.GEO_LOCATION_ME == null)
			{
				Driver.GEO_LOCATION_ME = new GEO_Location();				
			}
			
			analyze_input(args);
			
			//
			//Initialize OUI
			//
			driver.oui_parser = new OUI_Parser(OUI_Parser.OUI_PATH, true);
			
			//
			//resolve self ip
			//
			/*if(driver.my_external_ip_address == null || driver.my_external_ip_address.trim().equals("") || driver.GEO_LOCATION_ME == null)
				driver.my_external_ip_address = GEO_Location.resolve_self_ip(0);*/
			
			
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "Constructor - 1", e);
		}
	}
	
	public boolean print_interfaces()
	{
		try
		{
			configure_tshark_execution_path();
			
			list_interfaces = driver.list_interfaces(false, TSHARK_RUN_COMMAND);
			
			driver.print_linked_list("\nInterfaces found:", list_interfaces);
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "print_interfaces", e);
		}
		
		return false;
	}
	
	public boolean process_args(String [] args)
	{
		try
		{
			if(args.length > 0)
			{
				
				
				int i = 0;
				for(i = 0; i < args.length; i++)
				{
					arg = args[i];
					
					if(arg == null)
						continue;
					
					arg = arg.trim();
					
					//
					//interface
					//
					if(arg.toLowerCase().startsWith("-d") || arg.toLowerCase().startsWith("-list interface") || arg.toLowerCase().startsWith("-list_interface") || arg.toLowerCase().startsWith("list interface") || arg.toLowerCase().startsWith("list_interface"))
					{
						try
						{
							print_interfaces();
							//System.exit(0);
						}
						catch(Exception e){specific_interface = null;}
					}
					
					//
					//interface
					//
					if(arg.toLowerCase().startsWith("-i"))
					{
						try
						{
							specific_interface = args[++i];
							
							continue;
						}
						catch(Exception e){specific_interface = null;}
					}
					
					//
					//SENSOR port
					//
					else if(arg.toLowerCase().startsWith("-p"))
					{
						try
						{
							specific_SENSOR_port = Integer.parseInt(args[++i].trim());
							
							if(specific_SENSOR_port < 0)
								throw new Error("Invalid SENSOR port specified. Port should be greater than 0!");
							
							continue;
						}
						catch(Exception e)
						{
							driver.directive("ERROR! I am unable to determine your preferred SENSOR port. I am setting to default [" + SensorServerSocket.DEFAULT_PORT + "]");
							specific_SENSOR_port = SensorServerSocket.DEFAULT_PORT;
						}
					}
					
					//
					//PARSER port
					//
					else if(arg.toLowerCase().startsWith("-pp"))
					{
						try
						{
							specific_PARSER_port = Integer.parseInt(args[++i].trim());
							
							if(specific_PARSER_port < 0)
								throw new Error("Invalid PARSER port specified. Port should be greater than 0!");
							
							continue;
						}
						catch(Exception e)
						{
							driver.directive("ERROR! I am unable to determine your preferred PARSER port. I am setting to default [" + ParserServerSocket.DEFAULT_PARSER_PORT + "]");
							specific_PARSER_port = SensorServerSocket.DEFAULT_PARSER_PORT;
						}
					}
					
					//
					//
					//
					else if(arg.toLowerCase().startsWith("-e"))
					{
						try
						{
							encryption_key = args[++i];
							
							if(encryption_key != null)
							{
								encryption_key = encryption_key.trim();
								
								if(encryption_key.equals(""))
									encryption_key = null;
							}
							
							continue;
						}
						catch(Exception e){encryption_key = null;}
					}
					
					else if(arg.toLowerCase().startsWith("-n") || arg.toLowerCase().startsWith("-name") || arg.toLowerCase().startsWith("-sensor"))
					{
						try
						{
							sensor_name = args[++i];
							
							if(sensor_name != null)
							{
								sensor_name = sensor_name.replaceAll("\t", "").trim() + " ";
								
								if(sensor_name.trim().equals(""))
									sensor_name = "" + Driver.NAME + "_" + System.currentTimeMillis();
							}
							
							continue;
						}
						catch(Exception e){sensor_name = "" + Driver.NAME + "_" + System.currentTimeMillis();}
					}
				}
				
			}
			
			return true;
		}
		catch(Exception e)
		{
			driver.directive("Invalid input! Please check your arguments.  Restart program if necessary");
		}
		
		return false;
	}
	
	
	public boolean analyze_input(String [] args)
	{
		try
		{		
			//quick start, jump to avoid configuration if necessary
			if(args != null && args.length > 0)
			{
				for(String arg : args)
				{
					if(arg == null || arg.trim().equals(""))
						continue;
					
					//
					//interface
					//
					if(arg.toLowerCase().startsWith("-d") || arg.toLowerCase().startsWith("-list interface") || arg.toLowerCase().startsWith("-list_interface") || arg.toLowerCase().startsWith("list interface") || arg.toLowerCase().startsWith("list_interface"))
					{
						try
						{
							print_interfaces();
							System.exit(0);
						}
						catch(Exception e){specific_interface = null;}
					}
				}
			}
			
			//
			//determine if starting sensor, parser, or both
			//
			int selection = driver.jop_Query_Custom_Buttons("Please select configuration mode to start " + driver.NAME, "Specify Configuration Mode", new Object[]{"Start Sensor", "Start Parser", "Start BOTH Sensor and Parser"});
			
			switch(selection)
			{
				case 0:
				{
					START_SENSOR = true;
					break;
				}
				case 1:
				{
					START_PARSER = true;
					break;
				}
				case 2:
				{
					START_SENSOR = true;
					START_PARSER = true;
					START_BOTH_SENSOR_AND_PARSER = true;
					break;
				}
				default:
				{
					START_SENSOR = true;
					driver.directive("Initiating default action which is to start sensor!");					
					break;
				}
				
			}
															
			process_args(args);
			
			//
			//check if we're to query for encrytpion key
			//
			if(encryption_key == null)
			{
				String key = driver.jop_Query("Enter encryption key. ESC to leave encryption disabled", "Specfy Encryption key");
				
				if(key != null && !key.trim().equals(""))
					encryption_key = key.trim();
			}
			
			//
			//check if we're to query for encrytpion key
			//
			if(sensor_name.startsWith(Driver.NAME))
			{
				String name = driver.jop_Query("Sensor Name is currently set to [" + sensor_name + "].\nEnter a new name if you wish to change this designation:", "Specfy Sensor Name");
				
				if(name != null && !name.trim().equals(""))
					sensor_name = name.trim();
			}
			
			driver.directive("sensor name -->" + sensor_name);
			driver.directive("specific interface -->" + specific_interface);
			driver.directive("specific port -->" + specific_SENSOR_port);
			driver.directive("encryption_key -->" + encryption_key);
			
			
			if(this.START_BOTH_SENSOR_AND_PARSER)
			{
				configure_sensor();
				configure_parser(true);
				
				StandardInListener.launch_configuration_BOTH_SENSOR_AND_PARSER = true;
			}
			else if(this.START_SENSOR)
			{
				configure_sensor();
				StandardInListener.launch_configuration_SENSOR = true;
			}
			else if(this.START_PARSER)
			{
				configure_parser(true);
				Driver.sensor_output_enabled = false;
				StandardInListener.launch_configuration_PARSER = true;

			}
			
			configure_request_resolution_server_socket();
			
			configure_nmap();
			
			//
			//specify Gaius address [ephemeral port] 
			//
			if(GEO_Location.GLOBAL_GAIUS_CONNECTION_ADDRESS == null)
			{
				GEO_Location.set_gaius_address(null);												
			}
			
			//
			//specify Excalibur IDS Address
			//
			specify_excalibur_ids_address(null);
			
			//load the interface
			if(StandardInListener.launch_configuration_BOTH_SENSOR_AND_PARSER || this.START_PARSER)
			{
				driver.directive("\nI am about to configure the interface. Please standby...");
				
				if(StandardInListener.intrface == null)
					StandardInListener.intrface = new Interface();
				else
					driver.directive("PUNT! Interface is already instantiated!");
			}
			else
			{
				driver.directive("\nInterface can be instantiated by running the \"interface\" command. \nPress \"s\" to display status...Press \"sensor verbose\" to toggle verbosity of the sensor output.\n\n");
			}
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "analyze_input", e);			
		}
		
		return false;
	}
	
	public static String specify_excalibur_ids_address(String value)
	{
		try
		{	
			String EXCALIBUR_IDS_ADDRESS = null;
			int EXCALIBUR_IDS_PORT = -1;
			
			if(value == null || value.trim().equals(""))
				value = driver.jop_Query("Please enter address to Excalibur IDS instance:", "Specify Excalibur IDS Address");
			
			if(value == null || value.trim().equals(""))
			{
				driver.directive("Specify Address to Excalibur IDS instance canceled");
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
				
				EXCALIBUR_IDS_ADDRESS = value;
				EXCALIBUR_IDS_PORT = -1;
			}
			else if(array.length == 1)
			{
				EXCALIBUR_IDS_ADDRESS = value;
				EXCALIBUR_IDS_PORT = -1;
			}
			else
			{
				try
				{
					EXCALIBUR_IDS_PORT = Integer.parseInt(array[array.length-1].trim()); 
					
					EXCALIBUR_IDS_ADDRESS = array[0].trim();
					
					for(int i = 1; i < array.length-1; i++)
					{
						if(array[i].trim().equals(""))
							continue;
						
						EXCALIBUR_IDS_ADDRESS = EXCALIBUR_IDS_ADDRESS + ":" + array[i].trim();												
					}
				}
				catch(Exception ee)
				{
					driver.directive("* PUNT!!! It appears Port number [" + array[array.length-1] + "] was invalid or missing! Please provide via <IP Address> <PORT>");
					return null;
				}
			}
			
			Parser.GLOBAL_EXCALIBUR_IDS_CONNECTION_ADDRESS = EXCALIBUR_IDS_ADDRESS;
			Parser.GLOBAL_EXCALIBUR_IDS_CONNECTION_PORT = EXCALIBUR_IDS_PORT;
			
			if(EXCALIBUR_IDS_PORT > -1)
				driver.directive("\nEXCALIBUR_IDS Address is set to [" + EXCALIBUR_IDS_ADDRESS + "]  PORT [" + EXCALIBUR_IDS_PORT + "]\n");
			else
				driver.directive("\nGaius Address is set to [" + EXCALIBUR_IDS_ADDRESS + "].\n");
			
			//
			//CONNECT TO IDS WHOIS SERVER
			//
			try
			{
				Socket skt = new Socket(EXCALIBUR_IDS_ADDRESS, EXCALIBUR_IDS_PORT);
				
				Whois_IDS_ResolutionRequest_ThdSocket thd = new Whois_IDS_ResolutionRequest_ThdSocket(null, skt);
			}
			catch(Exception ee)
			{
				driver.directive("ERROR * * *  I was unable to establish a connection to resolution request server at --> " + EXCALIBUR_IDS_ADDRESS + " : " + EXCALIBUR_IDS_PORT);
			}
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "specify_excalibur_ids_address", e);
		}
		
		return null;
	}
	
	public static boolean configure_nmap()
	{
		try
		{
			if(driver.jop_Confirm("Would you like to enable nmap host network scanning\nto enumerate private hosts discovered on this network?", "Enable nmap Host Network Enumeration?") == JOptionPane.YES_OPTION)
			{
				//ensure we have path to nmap
				configure_nmap_execution_path();
				
				if(NMap.nmap_RUN_COMMAND == null || NMap.fleNmap == null || !NMap.fleNmap.isFile())
				{
					driver.directive("PUNT! No valid path was found to nmap binary. Halting nmap configuration");
					return false;
				}
				
				NMap.NMAP_ENABLED = true;				
				
			}
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "configure_namep");
		}
		
		return false;
	}
	
	public boolean configure_request_resolution_server_socket()
	{
		try
		{			
			//
			//PORT
			//
			String port = driver.jop_Query("[IDS] Whois Resolution Request Listen Port (ServerSocket) is currently set to [" + Whois_IDS_ResolutionRequest_ServerSocket.DEFAULT_PORT + "].\nEnter a new port number if you wish to change this configuration:", "Specify [IDS] Whois Resolution Request ServerSocket Port");
			int PORT = Whois_IDS_ResolutionRequest_ServerSocket.DEFAULT_PORT; 
			
			if(port != null && !port.trim().equals(""))
			{
				try
				{
					PORT = Integer.parseInt(port.trim()); 
					
					if(PORT < 0)
						throw new Exception("Port number must be greater than 0!");
				}
				catch(Exception e)
				{
					driver.jop_Error("Invalid port number specified! Attempting to establish on port [" + Whois_IDS_ResolutionRequest_ServerSocket.DEFAULT_PORT + "]", false);
					PORT = Whois_IDS_ResolutionRequest_ServerSocket.DEFAULT_PORT;
				}
			}
			
			resolution_serversocket = new Whois_IDS_ResolutionRequest_ServerSocket(PORT);
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "configure_request_resolution_server_socket", e);
		}
		
		return false;
	}
	
	public boolean configure_sensor()
	{
		try
		{
			//find tshark 
			driver.sop("Configuring system. Please standby...");
			
			configure_tshark_execution_path();
			
			driver.sop("Instantiation of tshark set to be -->"  + TSHARK_RUN_COMMAND);
			
			//list interfaces
			//LinkedList<String> list_interfaces = driver.list_interfaces(true, TSHARK_RUN_COMMAND);
			LinkedList<String> list_interfaces = driver.list_interfaces(false, TSHARK_RUN_COMMAND);
			
			driver.print_linked_list("Interfaces found:", list_interfaces);
			
			//
			//establish serversocket
			//
			if(specific_SENSOR_port == SensorServerSocket.DEFAULT_SENSOR_PORT)
			{
				String port = driver.jop_Query("Sensor Listen Port (ServerSocket) is currently set to [" + specific_SENSOR_port + "].\nEnter a new port number if you wish to change this configuration:", "Specfy Sensor ServerSocket Port");
				
				//user canceled action, skip
				if(port !=  null && !port.trim().equals(""))
				{
					try
					{
						specific_SENSOR_port = Integer.parseInt(port.trim());
						
						if(specific_SENSOR_port < 0)
							throw new Exception("Invalid port number. You can not specify a value less than 0.");
					}
					catch(Exception e)
					{
						specific_SENSOR_port = SensorServerSocket.DEFAULT_SENSOR_PORT;
						driver.jop_Error("Invalid port number received! I am setting back to default [" + specific_SENSOR_port + "]", false);
						driver.directive("Invalid port number received! I am setting back to default [" + specific_SENSOR_port + "]");
					}
				}
				
				//otw, we keep default port!
			}
			
			svrskt = new SensorServerSocket(specific_SENSOR_port);
			
			//
			//Establish sensors!
			//
			if((list_interfaces == null || list_interfaces.isEmpty()) && specific_interface == null)
			{
				driver.directive("\nPUNT!!!!!!! I was not able to locate a single interface to establish the sensors!");
			}
			
			if(specific_interface == null)
			{
				//query user if there is a specific interface
				try
				{
					driver.directive("Querying user for specific interface to establish sensor across...");
					
					if((driver.arr_tshark_interfaces == null || driver.arr_tshark_interfaces.length < 1) && list_interfaces != null && list_interfaces.size() > 0)
					{
						driver.arr_tshark_interfaces = new String[list_interfaces.size()];
						
						for(int i =0; i < list_interfaces.size(); i++)
						{
							driver.arr_tshark_interfaces[i] = list_interfaces.get(i);
						}
							
						use_interface_number = false;
					}


					String selection = ""+ driver.jop_queryJComboBox("Please select the specific interface to establish the sensor.\n\nPress escape to listen across all interfaces", "* Select Interface *", driver.arr_tshark_interfaces);
					
					if(selection != null)
						selection = selection.trim();
					
					if(selection.equals("") || selection.toLowerCase().trim().equals("null"))
						selection = null;
					
					if(selection != null)
					{
						specific_interface = selection.trim();
						
						if(use_interface_number || selection.contains("["))
						{
							String interface_number =  selection.substring(2, selection.indexOf("]")).trim();
							
							specific_interface = interface_number.trim();
						}												
					}
					
					
					
					
					
				}
				catch(Exception ee){}
						
			}
			
			if(specific_interface == null)
			{
				
				
				//configure sensor for each interface
				
				driver.directive("No specific interface was selected. I will attempt to instantiate sensor on all detected interfaces.");
				
				//since we're starting all sensors at the same time, some will fail since they're not applicable to tshark, so instead of having cascading errors, just dismiss each error
				Sensor.REVIVE_AFTER_DEATH = false;
				
				String iface = "";
				
				if((driver.arr_tshark_interfaces == null || driver.arr_tshark_interfaces.length < 1) && list_interfaces != null && list_interfaces.size() > 0)
				{
					driver.arr_tshark_interfaces = new String[list_interfaces.size()];					
				}
				
				/*for(int i = 0; i < list_interfaces.size(); i++)
				{
					iface = list_interfaces.get(i);
					
					if(driver.isLinux)
					{
						//only auto instantiate lo, eth's, and wlan's
						if(iface.toLowerCase().startsWith("eth") || iface.toLowerCase().startsWith("wlan") || iface.toLowerCase().equals("lo") || iface.toLowerCase().startsWith("mon"))
						{
							String command = TSHARK_RUN_COMMAND + " -i " + "\"" + iface + "\" " + SENSOR_PARAMETERS;
							
							Sensor sensor = new Sensor(command, iface);
						}
					}
					
					if(driver.isWindows)
					{
						
						String command = TSHARK_RUN_COMMAND + " -i " + (i+1) + " " + SENSOR_PARAMETERS;
						Sensor sensor = new Sensor(command, iface);											
					}									
				}*/
				
				String array [] = null;
				
				for(String interface_designation : driver.arr_tshark_interfaces)
				{
					if(interface_designation == null)
						continue;
					
					interface_designation = interface_designation.trim();
					
					if(interface_designation.equals(""))
						continue;
					
					specific_interface = interface_designation;
					
					if(driver.isWindows)
					{
						specific_interface =  interface_designation.substring(2, interface_designation.indexOf("]")).trim();
						
						String command = TSHARK_RUN_COMMAND + " -i " + "\"" + specific_interface + "\" " + SENSOR_PARAMETERS;
						Sensor sensor = new Sensor(command, specific_interface);
					}
					else
					{
						String command = TSHARK_RUN_COMMAND + " -i " + "\"" + interface_designation + "\" " + SENSOR_PARAMETERS;
						Sensor sensor = new Sensor(command, specific_interface);
					}
				}
			}
			else if(specific_interface != null)
			{
				//configure sensor for specific interface
				String command = TSHARK_RUN_COMMAND + " -i " + "\"" + specific_interface + "\" " + SENSOR_PARAMETERS;
				Sensor sensor = new Sensor(command, specific_interface);
			}
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "configure_sensor", e);
		}
		
		return false;
	}
	
	
	
	public static boolean configure_parser(boolean query_for_port)
	{
		try
		{
			//
			//establish serversocket
			//
			if(specific_PARSER_port == SensorServerSocket.DEFAULT_PARSER_PORT && query_for_port)
			{
				String port = driver.jop_Query("Parser Listen Port (ServerSocket) is currently set to [" + specific_PARSER_port + "].\nEnter a new port number if you wish to change this configuration:", "Specfy Parser ServerSocket Port");
				
				//user canceled action, skip
				if(port !=  null && !port.trim().equals(""))
				{
					try
					{
						specific_PARSER_port = Integer.parseInt(port.trim());
						
						if(specific_PARSER_port < 0)
							throw new Exception("Invalid PARSER port number. You can not specify a value less than 0.");
					}
					catch(Exception e)
					{
						specific_PARSER_port = SensorServerSocket.DEFAULT_PARSER_PORT;
						driver.jop_Error("Invalid PARSER port number received! I am setting back to default [" + specific_PARSER_port + "]", false);
						driver.directive("Invalid PARSER port number received! I am setting back to default [" + specific_PARSER_port + "]");
					}
				}
				
				//otw, we keep default port!
			}
			
			ParserServerSocket svrskt_parser = new ParserServerSocket(specific_PARSER_port);
			
			//configure interface if applicable
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "configure_parser", e);
		}
		
		return false;
	}
	
	public boolean configure_tshark_execution_path()
	{
		try
		{
			if(driver.isLinux)
			{
				//execute which cmd to ensure we have tshark configured on the machine
				try	
				{	
					Process p = Runtime.getRuntime().exec("which tshark");
					
					BufferedReader brIn = new BufferedReader(new InputStreamReader(p.getInputStream()));
					BufferedReader brIn_Error = new BufferedReader(new InputStreamReader(p.getErrorStream()));
					
					String tshark_path = brIn.readLine();
					String error = brIn_Error.readLine();
					
					if(tshark_path == null || tshark_path.trim().equals(""))
					{
						driver.directive("ERROR! I could not locate path to \"tshark\"! Your system may not be configured properly. \nPlease install tshark before using this sensor!");
						
						if(error != null && !error.trim().equals(""))
						{
							driver.directive("Error Message: \"" + error + "\"");
						}
						
						File fle_tshark = driver.querySelectFile(true, "Please select path to tshark.exe", JFileChooser.FILES_ONLY, false, false);
						
						if(fle_tshark!= null && fle_tshark.exists() && fle_tshark.isFile())
						{
							tshark_path = fle_tshark.getCanonicalPath();
							TSHARK_RUN_COMMAND = "\"" + fle_tshark.getCanonicalPath() + "\"";
						}
						
						else
						{
							driver.jop_Error("ERROR! I cannot find path to tshark.exe. \nPlease configure your system appropriately and then try again in order to ensure\nproper execution of " + driver.FULL_NAME, false);
						}
					}
					
					else
					{
						//driver.directive("tshark was located at -->" + tshark_path);
						//TSHARK_RUN_COMMAND = tshark_path ;
					}
					


				}
				
				catch(Exception e)
				{
					driver.directive("\nPUNT! I encountered an error when attempting to execute the which command\n!");
				}
				
			}
			
			else if(driver.isWindows)
			{
				//check program files for tshark, query user for tshark file if not found
				
				Process p = Runtime.getRuntime().exec("cmd.exe /C \"echo %programfiles%\\wireshark\\tshark.exe\"");
				
				BufferedReader brIn = new BufferedReader(new InputStreamReader(p.getInputStream()));
				BufferedReader brIn_Error = new BufferedReader(new InputStreamReader(p.getErrorStream()));
				
				String tshark_path = brIn.readLine();
				String error = brIn_Error.readLine();
				
				if(tshark_path == null || tshark_path.trim().equals(""))
				{
					driver.directive("ERROR! I could not locate path to \"tshark\"! Your system may not be configured properly. \nPlease install tshark before using this sensor!");
					
					if(error != null && !error.trim().equals(""))
					{
						driver.directive("Error Message: \"" + error + "\"");
					}
				}
				
				//driver.directive("tshark was located at -->" + tshark_path);
				TSHARK_RUN_COMMAND = "\"" + tshark_path + "\"";										
				
				//ensure true file
				File fle_tshark = new File(tshark_path);
				
				if(!fle_tshark.exists() || !fle_tshark.isFile())
				{
					driver.directive("ERROR! I cannot location path to tshark.exe. I will query user for tshark.exe path now...");
					
					fle_tshark = driver.querySelectFile(true, "Please select path to tshark.exe", JFileChooser.FILES_ONLY, false, false);
					
					if(fle_tshark!= null && fle_tshark.exists() && fle_tshark.isFile())
					{
						TSHARK_RUN_COMMAND = "\"" + fle_tshark.getCanonicalPath() + "\"";
					}
					
					else
					{
						driver.jop_Error("ERROR! I cannot find path to tshark.exe. \nPlease configure your system appropriately and then try again in order to ensure\nproper execution of " + driver.FULL_NAME, false);
					}
					
				}
				else
				{
					TSHARK_RUN_COMMAND = "\"" + fle_tshark.getCanonicalPath() + "\"";
				}
				
				//driver.directive("FINAL PATH -->" + TSHARK_RUN_COMMAND);
				
			}
			
			else
			{
				driver.directive("PUNT! I am unable to determine path to wireshark on this operating system! Execution may be unstable as a result...");
			}
			
			
			
			return true;
		}
		
		catch(Exception e)
		{
			driver.eop(myClassName, "configure_tshark_execution_path", e, true);
		}
		
		return false;
	}
	
	
	
	//https://nmap.org/download.html
	//ipconfig | findstr /i "Gateway"
	//ip route | grep default
	//mac: netstat -nr | grep default
	
	//split the array, take the first value that comes out to be an ipv4
	//if fail, ask user to enter gateway address
	
	
	
	public static boolean configure_nmap_execution_path()
	{
		try
		{
			if(driver.isLinux)
			{
				//execute which cmd to ensure we have nmap configured on the machine
				try	
				{	
					Process p = Runtime.getRuntime().exec("which nmap");
					
					BufferedReader brIn = new BufferedReader(new InputStreamReader(p.getInputStream()));
					BufferedReader brIn_Error = new BufferedReader(new InputStreamReader(p.getErrorStream()));
					
					String nmap_path = brIn.readLine();
					String error = brIn_Error.readLine();
					
					if(nmap_path == null || nmap_path.trim().equals(""))
					{
						driver.directive("ERROR! I could not locate path to \"nmap\"! Your system may not be configured properly. \nPlease install nmap before using this sensor!");
						
						if(error != null && !error.trim().equals(""))
						{
							driver.directive("Error Message: \"" + error + "\"");
						}
						
						driver.jop_Error("NOTE! I cannot find path to nmap.exe.  \n\nIt could be the case that nmap is not installed or properly configured on this machine. \nInstall nmap on this machine if applicable before continuing further...\nI will query user for the executable path...", false);
						
						File fle_nmap = driver.querySelectFile(true, "Please select path to nmap.exe", JFileChooser.FILES_ONLY, false, false);
						
						if(fle_nmap!= null && fle_nmap.exists() && fle_nmap.isFile())
						{
							nmap_path = fle_nmap.getCanonicalPath();
							NMap.nmap_RUN_COMMAND = fle_nmap.getCanonicalPath();
						}
						
						else
						{
							driver.jop_Error("ERROR! I cannot find path to nmap.exe. \nPlease configure your system appropriately and then try again in order to ensure\nproper execution of " + driver.FULL_NAME, false);
						}
					}
					
					else
					{
						//driver.directive("nmap was located at -->" + nmap_path);
						//nmap_RUN_COMMAND = nmap_path ;
					}
					


				}
				
				catch(Exception e)
				{
					driver.directive("\nPUNT! I encountered an error when attempting to execute the which command\n!");
				}
				
			}
			
			else if(driver.isWindows)
			{
				//check program files for nmap, query user for nmap file if not found
				
				Process p = Runtime.getRuntime().exec("cmd.exe /C \"echo %ProgramFiles(x86)%\\nmap\\nmap.exe\"");
				
				BufferedReader brIn = new BufferedReader(new InputStreamReader(p.getInputStream()));
				BufferedReader brIn_Error = new BufferedReader(new InputStreamReader(p.getErrorStream()));
				
				String nmap_path = brIn.readLine();
				String error = brIn_Error.readLine();
				
				if(nmap_path == null || nmap_path.trim().equals(""))
				{
					driver.directive("ERROR! I could not locate path to \"nmap\"! Your system may not be configured properly. \nPlease install nmap before using this sensor!");
					
					if(error != null && !error.trim().equals(""))
					{
						driver.directive("Error Message: \"" + error + "\"");
					}
				}
				
				//driver.directive("nmap was located at -->" + nmap_path);
				NMap.nmap_RUN_COMMAND = nmap_path;										
				
				//ensure true file
				File fle_nmap = new File(nmap_path);
				
				if(!fle_nmap.exists() || !fle_nmap.isFile())
				{
					driver.directive("\nERROR! I cannot location path to nmap.exe. I will query user for nmap.exe path now...");
					
					driver.jop_Error("NOTE! I cannot find path to nmap.exe.  \n\nIt could be the case that nmap is not installed or properly configured on this machine. \nInstall nmap if applicable before continuing further... \nI will query user for the executable path...", false);
					
					
					fle_nmap = driver.querySelectFile(true, "Please select path to nmap.exe", JFileChooser.FILES_ONLY, false, false);
					
					if(fle_nmap!= null && fle_nmap.exists() && fle_nmap.isFile())
					{
						NMap.nmap_RUN_COMMAND = fle_nmap.getCanonicalPath();
					}
					
					else
					{
						driver.jop_Error("ERROR! I cannot find path to nmap.exe. \nPlease configure your system appropriately and then try again in order to ensure\nproper execution of " + driver.FULL_NAME, false);
					}
					
				}
				else
				{
					NMap.nmap_RUN_COMMAND = fle_nmap.getCanonicalPath();
				}
				
				//driver.directive("FINAL PATH -->" + nmap_RUN_COMMAND);
				
			}
			
			else
			{
				driver.directive("PUNT! I am unable to determine path to nmap on this operating system! Execution may be unstable as a result...");
			}
			
			//conduct final check if we have a file
			
			try
			{
				File fle = new File(NMap.nmap_RUN_COMMAND);
				
				if(fle.exists() && fle.isFile())
				{
					NMap.fleNmap = fle;
					NMap.nmap_RUN_COMMAND = "\"" + NMap.fleNmap.getCanonicalPath() + "\"";
				}
				else
					NMap.nmap_RUN_COMMAND = null;
			}
			
			catch(Exception e){NMap.nmap_RUN_COMMAND = null;}
			
			return true;
		}
		
		catch(Exception e)
		{
			driver.eop(myClassName, "configure_nmap_execution_path", e, true);
		}
		
		return false;
	}
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
}
