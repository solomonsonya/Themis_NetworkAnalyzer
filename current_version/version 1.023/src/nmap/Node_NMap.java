/**
 * Once we receive a "Host is up" notification from the nmap scan, this is our signal to create a new node to store
 * 
 * @author Solomon Sonya
 */

package nmap;

import Driver.*;
import Profile.*;
import Driver.*;
import java.util.*;
import javax.swing.JFileChooser;
import java.net.*;
import java.io.*;

public class Node_NMap 
{
	public static final String myClassName = "Node_NMap";
	public volatile static Driver driver = new Driver();
	
	public static volatile TreeMap<String, Node_NMap> TREE_NMAP_NODES = new TreeMap<String, Node_NMap>();
	
	public volatile String contents = "";
	
	public volatile String data_summary = "";
	
	/**Nmap scan report for 192.168.0.1*/
	public volatile String  address = "";
	
	/**OUT Company Name e.g. VMWare, Apple Inc, etc*/
	public volatile String oui = "";
	
	/**Not shown: 998 closed ports*/
	public volatile String  not_shown = "";
	
	/**80/tcp open  http    DD-WRT milli_httpd*/
	public volatile LinkedList<String>  list_open_ports = new LinkedList<String>();
	
	/**MAC Address: C8:D3:A3:59:7B:F4 (D-Link International)*/
	public volatile String  mac_address = "";
	
	/**Device type: general purpose*/
	public volatile String  device_type = "";
	
	/**Running: Linux 2.6.X*/
	public volatile String  running = "";
	
	/**OS CPE:*/
	public volatile String  os_cpe = "";
	
	/**OS details: Linux 2.6.9 - 2.6.27*/
	public volatile String  os_details = "";
	
	/**Network Distance: 1 hop*/
	public volatile String  network_distance = "";
	
	/**Service Info: OS: Linux; Device: WAP; CPE: cpe:/o:linux:linux_kernel*/
	public volatile String  service_info = "";
	
	/**Service Info: OS: Linux; Device: WAP; CPE: cpe:/o:linux:linux_kernel*/
	public volatile String  os_SERVICE_INFO = "";
	
	/**Service Info: OS: Linux; Device: WAP; CPE: cpe:/o:linux:linux_kernel*/
	public volatile String  device_SERVICE_INFO = "";
	
	/**Service Info: OS: Linux; Device: WAP; CPE: cpe:/o:linux:linux_kernel*/
	public volatile String  CPE_SERVICE_INFO = "";
	
	/**Service Info: Host: WIN-JEF9LLV3T02; OS: Windows; CPE: cpe:/o:microsoft:windows*/
	public volatile String  host_name = "";
	
	/**NetBIOS user: <unknown>,*/
	public volatile String user = "";
	
	/** Workgroup: WORKGROUP\x00*/
	public volatile String workgroup = "";
	
	/** System time: 2018-02-07T22:26:25-07:00*/
	public volatile String system_time = "";
	
	/**  account_used: <blank>*/
	public volatile String account_used = "";
	
	/** authentication_level: user*/
	public volatile String authentication_level = "";
	
	/** message_signing: disabled (dangerous, but default)*/
	public volatile String message_signing = "";
	
	/** challenge_response: supported*/
	public volatile String challenge_response = "";
	
	/**start_date: 2018-02-06 19:52:55*/
	public volatile String start_date = "";
	
	public volatile String [] array = new String[21];
	
	public Node_NMap(String addr)
	{
		try
		{
			address = addr;
			
			try	{	TREE_NMAP_NODES.put(addr,  this);	}	catch(Exception e){}
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "Constructor - 1", e);
		}
	}
	
	
	public String toString(LinkedList<String> list, String delimiter)
	{
		try
		{
			if(list == null || list.isEmpty())
				return "";
			
			contents = list.getFirst();
			
			for(int i = 1; i < list.size(); i++)
			{
				contents = contents + delimiter + list.get(i);
			}
			
			return contents;			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "toString", e);
		}
		
		return contents;
	}
	
	public String [] get_jtable_row()
	{
		try
		{						
			array[0] = this.address;
			array[1] = this.mac_address;
			array[2] = this.host_name;
			array[3] = this.toString(this.list_open_ports, ", ");
			array[4] = this.running;
			array[5] = this.device_type;
			array[6] = this.device_SERVICE_INFO;
			array[7] = this.os_SERVICE_INFO;
			array[8] = this.CPE_SERVICE_INFO;
			array[9] = this.os_cpe;
			array[10] = this.os_details;
			array[11] = this.network_distance;
			array[12] = this.service_info;
			array[13] = this.user;
			array[14] = this.workgroup;
			array[15] = this.system_time;
			array[16] = this.account_used;
			array[17] = this.authentication_level;
			array[18] = this.challenge_response;
			array[19] = this.message_signing;
			array[20] = this.start_date;
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "get_jtable_row", e);
		}
		
		return array;
	}
	
	
	public String get_data_row_summary(String delimiter)
	{
		try
		{
			
			
			data_summary = "Host Address: " + address + delimiter;
			
			if(mac_address != null && !mac_address.trim().equals(""))
				data_summary = data_summary + "MAC Address: " + mac_address.trim() + delimiter;
			
			if(host_name != null && !host_name.trim().equals(""))
				data_summary = data_summary + "Host Name: " + host_name.trim() + delimiter;
			
			if(this.list_open_ports != null && !this.list_open_ports.isEmpty())
				data_summary = data_summary + "\nOpen Port Summary: " + delimiter + "\t"+ toString(list_open_ports, delimiter + "\t");
			
			if(running != null && !running.trim().equals(""))
				data_summary = data_summary + "Running OS: " + running.trim() + delimiter;
			
			if(device_type != null && !device_type.trim().equals(""))
				data_summary = data_summary + "Device Type: " + device_type.trim() + delimiter;
			
			if(device_SERVICE_INFO != null && !device_SERVICE_INFO.trim().equals(""))
				data_summary = data_summary + "Device: " + device_SERVICE_INFO.trim() + delimiter;
			
			if(os_SERVICE_INFO != null && !os_SERVICE_INFO.trim().equals(""))
				data_summary = data_summary + "OS: " + os_SERVICE_INFO.trim() + delimiter;
			
			if(CPE_SERVICE_INFO != null && !CPE_SERVICE_INFO.trim().equals(""))
				data_summary = data_summary + "Common Platform Enumeration (CPE): " + CPE_SERVICE_INFO.trim() + delimiter;
			
			if(os_cpe != null && !os_cpe.trim().equals(""))
				data_summary = data_summary + "OS Common Platform Enumeration: " + os_cpe.trim() + delimiter;
			
			if(os_details != null && !os_details.trim().equals(""))
				data_summary = data_summary + "OS Details: " + os_details.trim() + delimiter;
			
			if(network_distance != null && !network_distance.trim().equals(""))
				data_summary = data_summary + "Network Distance to Host: " + network_distance.trim() + delimiter;
			
			if(service_info != null && !service_info.trim().equals(""))
				data_summary = data_summary + "Service Info: " + service_info.trim() + delimiter;
			
			if(user != null && !user.trim().equals(""))
				data_summary = data_summary + "NetBIOS User: " + user.trim() + delimiter;
			
			if(workgroup != null && !workgroup.trim().equals(""))
				data_summary = data_summary + "NetBIOS Workgroup: " + workgroup.trim() + delimiter;
			
			if(system_time != null && !system_time.trim().equals(""))
				data_summary = data_summary + "System Time during Scan: " + system_time.trim() + delimiter;
			
			if(account_used != null && !account_used.trim().equals(""))
				data_summary = data_summary + "NetBIOS Account Used: " + account_used.trim() + delimiter;
			
			if(authentication_level != null && !authentication_level.trim().equals(""))
				data_summary = data_summary + "NetBIOS Authentication Level: " + authentication_level.trim() + delimiter;
			
			if(challenge_response != null && !challenge_response.trim().equals(""))
				data_summary = data_summary + "NetBIOS Challenge Response: " + challenge_response.trim() + delimiter;
			
			if(message_signing != null && !message_signing.trim().equals(""))
				data_summary = data_summary + "Message Signing: " + message_signing.trim() + delimiter;
			
			if(start_date != null && !start_date.trim().equals(""))
				data_summary = data_summary + "System Start Time: " + start_date.trim() + delimiter;
			
			
			
					

		}
		catch(Exception e)
		{
			driver.eop(myClassName, "get_data_row_summary", e);
		}
		
		return data_summary;
	}
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	

}
