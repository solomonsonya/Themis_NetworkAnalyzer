package nmap;

import Driver.*;
import OUI_Parser.Node_OUI;
import Profile.*;
import Driver.*;
import java.util.*;

import javax.swing.JFileChooser;

import java.net.*;
import java.io.*;

public class NMap extends Thread implements Runnable
{
	
	public static final String myClassName = "NMap";
	public volatile static Driver driver = new Driver();
	
	public volatile Log log_nmap = null;
	
	public static volatile File fleNmap = null;
	public static volatile boolean NMAP_ENABLED = false;
	public static volatile boolean OUTPUT_ENABLED = true;
	public static volatile String nmap_RUN_COMMAND = "nmap";
	
	public volatile BufferedReader brIn = null;
	public volatile BufferedReader brIn_Error = null;
	public volatile PrintWriter pwOut = null;
	
	public static volatile LinkedList<NMap> list_working_nmap_daemons = new LinkedList<NMap>();
	
	public volatile boolean actions_complete = false;
	
	public static volatile boolean update_required = false;
	
	public volatile Node_NMap node_nmap = null;
	
	public volatile SOURCE ndeSource = null;
	
	public volatile File fleImport = null;
	
	public volatile String IP_TO_SCAN = "";
	public volatile String my_scan_ip = "";
	
	public volatile String lower = "";
	public volatile String trimmed = "";
	
	public static boolean decoys_enabled = false;
	
	/**Nmap scan report for 192.168.0.1*/
	public volatile String result_address = "";
	
	/**Not shown: 998 closed ports*/
	public volatile String result_not_shown = "";
	
	/**80/tcp open  http    DD-WRT milli_httpd*/
	public volatile LinkedList<String> result_list_open_ports = new LinkedList<String>();
	
	/**MAC Address: C8:D3:A3:59:7B:F4 (D-Link International)*/
	public volatile String result_mac_address = "";
	
	/**Device type: general purpose*/
	public volatile String result_device_type = "";
	
	/**Running: Linux 2.6.X*/
	public volatile String result_running = "";
	
	/**OS CPE:*/
	public volatile String result_os_cpe = "";
	
	/**OS details: Linux 2.6.9 - 2.6.27*/
	public volatile String result_os_details = "";
	
	/**Network Distance: 1 hop*/
	public volatile String result_network_distance = "";
	
	/**Service Info: OS: Linux; Device: WAP; CPE: cpe:/o:linux:linux_kernel*/
	public volatile String result_service_info = "";
	
	/**Service Info: OS: Linux; Device: WAP; CPE: cpe:/o:linux:linux_kernel*/
	public volatile String result_os_SERVICE_INFO = "";
	
	/**Service Info: OS: Linux; Device: WAP; CPE: cpe:/o:linux:linux_kernel*/
	public volatile String result_device_SERVICE_INFO = "";
	
	/**Service Info: OS: Linux; Device: WAP; CPE: cpe:/o:linux:linux_kernel*/
	public volatile String result_CPE_SERVICE_INFO = "";
	
	/**Service Info: Host: WIN-JEF9LLV3T02; OS: Windows; CPE: cpe:/o:microsoft:windows*/
	public volatile String result_host_SERVICE_INFO = "";
	
	//|_nbstat: NetBIOS name: WIN-JEF9LLV3T02, NetBIOS user: <unknown>, NetBIOS MAC: 00:0c:29:6e:b3:62 (VMware)

	
	
	
	
	
	public NMap(File fle)
	{
		try
		{
			fleImport = fle;
			this.import_data_file(fle);
		}
		
		catch(Exception e)
		{
			driver.eop(myClassName, "Constructor - 1", e);
		}
	}
	
	public NMap(SOURCE src, String ip)
	{
		try
		{
			ndeSource = src;			
			IP_TO_SCAN = ip;
			
			if(NMAP_ENABLED && fleNmap != null && fleNmap.exists())
			{
				this.start();
			}
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "Constructor - 2", e);
		}
	}
	
	public void run()
	{
		try
		{
			scan(this.IP_TO_SCAN);
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "run", e);
		}
	}
	
	public boolean scan(String ip)
	{
		try
		{
			if(this.fleNmap == null || !fleNmap.exists() || !NMAP_ENABLED)
				return false;								
			
			if(ip == null)
				return false;
			
			ip = ip.trim();
			
			//dismiss a few 
			if(ip.startsWith("0"))
				return false;
			
			my_scan_ip = ip;
			
			
			String decoys  = "";
			String network = "";
			
			if(decoys_enabled)
			{
				try
				{
					network = ip.substring(0, ip.lastIndexOf(".")); 

					decoys = " -D " + network + "." + (int)(Math.random() * 254);
					
					for(int i = 0; i < 6; i++)
						decoys = decoys + ", " + network + "." + (int)(Math.random() * 254);
				}
				
				catch(Exception e)
				{
					decoys = "";
				}
			}
			
			String command = nmap_RUN_COMMAND + " -A " + ip + decoys + " -T4 -Pn -v";
			
			
			Process p = null;
			
			if(driver.isWindows)
			{
				p = Runtime.getRuntime().exec("cmd.exe /C " + "\"" + command + "\"");
			}
			else if(driver.isLinux)
			{
				String [] cmd = new String [] {"/bin/bash", "-c", command};
				p = Runtime.getRuntime().exec(cmd);									
			}
			
			
			
			brIn = new BufferedReader(new InputStreamReader(p.getInputStream()));
			brIn_Error = new BufferedReader(new InputStreamReader(p.getErrorStream()));
			pwOut = new PrintWriter(new OutputStreamWriter(p.getOutputStream()), true);
			
			String line = "";
			
			try	{	list_working_nmap_daemons.add(this);	}	catch(Exception e){}
			
			while((line = brIn.readLine()) != null)
			{
				if(line.trim().equals(""))
					continue;
				
				sop(line);
				
				process_line(line);
			}
			
			while((line = brIn_Error.readLine()) != null)
			{
				sop("[ERROR] --> " + line);
			}
			
			try	{	brIn.close();} catch(Exception e){}
			try	{	brIn_Error.close();} catch(Exception e){}
			try	{	pwOut.close();} catch(Exception e){}
			try	{	log_nmap.log(Log.END_LOG_OPEN_FILE_DO_NOT_OPEN_WHEN_COMPLETE);}	catch(Exception e){}

			actions_complete = true;
			
			try	{	list_working_nmap_daemons.remove(this);	}	catch(Exception e){}
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "scan", e);
		}
		
		return false;
	}
	
	public boolean sop(String out)
	{
		try
		{
			if(StandardInListener.intrface != null && StandardInListener.intrface.jpnlNetworkMap != null && OUTPUT_ENABLED)
				StandardInListener.intrface.jpnlNetworkMap.jta.append("[" + this.my_scan_ip + "] --> " + out + "\n");
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "sop", e);
		}
		
		return false;
	}
	
	public boolean import_data_file(File fle)
	{
		try
		{
			if(fle == null || !fle.exists() || !fle.isFile())
			{
				fle = driver.querySelectFile(true, "Please select nmap file to import...", JFileChooser.OPEN_DIALOG, false, false);
			}
			
			if(fle == null || !fle.exists() || !fle.isFile())
			{
				driver.directive("No file selected or selected file is invalid... Punting for now...");
				return false;
			}
			
			driver.directive("\nCommencing nmap read on file --> " + fle.getCanonicalPath());
			
			String line = "";
			BufferedReader brIn = new BufferedReader(new FileReader(fle));
			int num_lines = 0;
			while((line = brIn.readLine()) != null)
			{
				line = line.trim();
				
				if(line.equals(""))
					continue;
				
				if(line.startsWith("#"))
					continue;
				
				this.process_line(line);						
				
				++num_lines;
			}
			
			try	{ brIn.close();} catch(Exception e){}
			
			actions_complete = true;			
			update_required = true;
			
			driver.directive("Complete! Num lines read: [" + num_lines + "] on file --> " + fle.getCanonicalPath());
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "import_data_file", e);
		}
		
		return false;
	}
	
	public boolean reset_scan_values()
	{
		try
		{
			result_address = "";
			result_not_shown = "";
			try	{	this.result_list_open_ports.clear();} catch(Exception e){result_list_open_ports = new LinkedList<String>();}
			result_mac_address = "";
			result_device_type = "";
			result_running = "";
			result_os_cpe = "";
			result_os_details = "";
			result_network_distance = "";
			result_service_info = "";
			result_os_SERVICE_INFO = "";
			result_device_SERVICE_INFO = "";
			result_CPE_SERVICE_INFO = "";
			result_host_SERVICE_INFO = "";
			
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "reset_scan_values", e);
		}
		
		return false;
	}
	
	/**
	 * 
	 * @param line
	 * @return
	 */
	public boolean process_line(String line)
	{
		try
		{
			if(line.trim().equals(""))
				return false;
			
			
			
			
			trimmed = line.trim();
			
			
			if(trimmed.startsWith("|_"))
				trimmed = trimmed.substring(2).trim();
			if(trimmed.startsWith("|"))
				trimmed = trimmed.substring(1).trim();
									
			lower = trimmed.toLowerCase().trim();
			
			if(lower.startsWith("nmap scan report for"))
			{
				reset_scan_values();
				this.result_address = trimmed.substring(21).trim();
			}
			
			else if(lower.startsWith("host is up"))
			{
				//this is our signal to add the host node
				node_nmap = new Node_NMap(result_address);
				NMap.update_required = true;
			}
			
			//only proceed further if we have a new node we're dealing with
			if(node_nmap != null)
			{
				//
				//not shown
				//
				if(lower.startsWith("not shown"))
				{
					result_not_shown = trimmed.substring(11).trim();
					node_nmap.not_shown = result_not_shown;
				}
				
				//
				//PORT   STATE SERVICE VERSION
				//53/tcp open  domain  dnsmasq 2.41
				//
				else if(lower.contains("/") && lower.contains(" open "))
				{
					this.result_list_open_ports.add(trimmed);
					node_nmap.list_open_ports.add(trimmed);
				}
				
				//
				//result_mac_address
				//
				else if(lower.startsWith("mac address"))
				{
					this.result_mac_address = trimmed.substring(12).trim();
					node_nmap.mac_address = result_mac_address;
					
					node_nmap.oui = Node_OUI.getMAC_OUI_Company_Name(result_mac_address);
				}
				
				//
				//Device type
				//
				else if(lower.startsWith("device type"))
				{
					this.result_device_type = trimmed.substring(12).trim();
					node_nmap.device_type = result_device_type;
				}
				
				//
				//Running
				//
				else if(lower.startsWith("running"))
				{
					this.result_running = trimmed.substring(8).trim();
					node_nmap.running = result_running;
				}
				
				//
				//OS CPE
				//
				else if(lower.startsWith("os cpe"))
				{
					this.result_os_cpe = trimmed.substring(7).trim();
					
					if(result_os_cpe.toLowerCase().startsWith("cpe"))
						result_os_cpe = result_os_cpe.substring(4);
					
					node_nmap.os_cpe = result_os_cpe;
				}
				
				//
				//OS 				
				//
				else if(lower.startsWith("os:"))
				{
					node_nmap.os_SERVICE_INFO = trimmed.substring(3).trim();
				}
				
				//
				//
				//
				else if(lower.startsWith("os details"))
				{
					this.result_os_details = trimmed.substring(11).trim();
					node_nmap.os_details = result_os_details;
				}
				
				//
				//Network Distance:
				//
				else if(lower.startsWith("network distance"))
				{
					this.result_network_distance = trimmed.substring(17).trim();
					node_nmap.network_distance = result_network_distance;
				}
				
				
				//
				//Service Info:
				//
				else if(lower.startsWith("service info"))
				{
					this.result_service_info = trimmed.substring(13).trim();
					node_nmap.service_info = result_service_info;
					
					try
					{
						String str = result_service_info;
						
						String [] arr = str.split(";");
						
						for(String token : arr)
						{
							if(token.toLowerCase().trim().startsWith("os"))
								node_nmap.os_SERVICE_INFO = token.trim().substring(3).trim();
							else if(token.toLowerCase().trim().startsWith("device"))
								node_nmap.device_SERVICE_INFO = token.trim().substring(7).trim();
							else if(token.toLowerCase().trim().startsWith("cpe"))
							{
								node_nmap.CPE_SERVICE_INFO = token.trim().substring(4).trim();
								
								if(node_nmap.CPE_SERVICE_INFO.toLowerCase().trim().startsWith("cpe"))
									node_nmap.CPE_SERVICE_INFO = node_nmap.CPE_SERVICE_INFO.trim().substring(4).trim();
								if(node_nmap.CPE_SERVICE_INFO.toLowerCase().trim().startsWith("/o:"))
									node_nmap.CPE_SERVICE_INFO = node_nmap.CPE_SERVICE_INFO.trim().substring(3).trim();
							}
							else if(token.toLowerCase().trim().startsWith("host"))
								node_nmap.host_name = token.trim().substring(5).trim();
						}
					}
					catch(Exception e){}
					
					
				}
				
				else if(lower.startsWith("nbstat: "))
				{
					try
					{
						lower = trimmed.substring(8).trim();
						
						String [] arr = lower.split(",");
						
						for(String token : arr)
						{
							token = token.trim();
							
							if(token.toLowerCase().startsWith("netbios name"))
								node_nmap.host_name = token.substring(13).trim();
							else if(token.toLowerCase().startsWith("netbios user"))
								node_nmap.user = token.substring(13).trim();
							else if(token.toLowerCase().startsWith("netbios mac"))
								node_nmap.mac_address = token.substring(12).trim();
						}
					}
					catch(Exception e){}
				}
				
				
				else if(lower.startsWith("computer name"))
				{
					node_nmap.host_name = trimmed.substring(14).trim();
				}
				
				else if(lower.startsWith("workgroup"))
				{
					node_nmap.workgroup = trimmed.substring(10).trim();
				}
				
				else if(lower.startsWith("system time"))
				{
					node_nmap.system_time = trimmed.substring(12).trim();
				}
				
				else if(lower.startsWith("account_used"))
				{
					node_nmap.account_used = trimmed.substring(13).trim();
				}
				
				else if(lower.startsWith("authentication_level"))
				{
					node_nmap.authentication_level = trimmed.substring(21).trim();
				}
				
				else if(lower.startsWith("challenge_response"))
				{
					node_nmap.challenge_response = trimmed.substring(19).trim();
				}
				
				else if(lower.startsWith("message_signing"))
				{
					node_nmap.message_signing = trimmed.substring(16).trim();
				}
				
				else if(lower.startsWith("start_date"))
				{
					node_nmap.start_date = trimmed.substring(11).trim();
				}
				
				
			}
			
			log(line);
			
			return true;
		}
		
		catch(Exception e)
		{
			driver.eop(myClassName, "process_line", e);
		}
		
		return false;
	}
	
	public boolean log(String line)
	{
		try
		{
			//
			//log dns resolution
			//
			if(log_nmap == null)
			{
				log_nmap = new Log("network_map/nmap_results/",  "nmap_" + this.my_scan_ip, 250, 999999999);
				log_nmap.OVERRIDE_LOGGING_ENABLED = true;
			}
			
			log_nmap.log_directly(line);
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "log", e);
		}
		
		return false;
	}

}
