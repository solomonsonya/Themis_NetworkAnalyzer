/**
 * This is the source node.  In a network communication, there is a source and destination communicating agents. 
 * 
 * This source is the node responsible for transmitting packets on a network.  At times, the source node will be the host system on our enclave, 
 * at times, the source will be the distant end communicating back to a system on our enclave. At other times, the source may even be gratuitous agents wishing to introduce
 * unsolicited packets onto our network.  This node captures the communications received from a source agent by the sensor
 * 
 * @author Solomon Sonya
 */

package Profile;

import Driver.*;
import OUI_Parser.*;
import Parser.Application;
import Parser.Artifact;
import nmap.NMap;
import GEO_Location.*;
import Map.Node_Map_Details;

import java.util.*;
import Profile.*;
import Whois_IDS_ResolutionRequest.Whois_IDS_ResolutionRequest_ThdSocket;

public class SOURCE 
{
	public static final String myClassName = "SOURCE";
	public volatile Driver driver = new Driver();

	/**KEY == SOURCE IP. When in doubt, use this one!*/
	public volatile static TreeMap<String, SOURCE> TREE_SOURCE_NODES = new TreeMap<String, SOURCE>();
	
	/**KEY == SOURCE MAC*/
	public volatile static TreeMap<String, SOURCE> tree_source_nodes_MAC = new TreeMap<String, SOURCE>();
	
	public volatile Resolution resolution = null, resolution_search = null;
	public volatile TreeMap<String, Resolution> tree_my_dst_macs = new TreeMap<String, Resolution>();
	public volatile TreeMap<String, Resolution> tree_my_dst_ip = new TreeMap<String, Resolution>();
	
	public volatile String value_map = "";
	
	/**trimmed requestes s.t. www.excite.com and excite.com/123.exe all come out to be excite.com*/
	public volatile TreeMap<String, Resolution> tree_my_domain_name_requests = new TreeMap<String, Resolution>();
	public volatile TreeMap<String, Resolution> tree_my_http_referer = new TreeMap<String, Resolution>();
	public volatile TreeMap<String, Resolution> tree_my_cookie = new TreeMap<String, Resolution>();
	public volatile TreeMap<String, Resolution> tree_my_http_host_virtual = new TreeMap<String, Resolution>();
	public volatile TreeMap<String, User_Agent> tree_my_user_agent = new TreeMap<String, User_Agent>();
	/*public volatile TreeMap<String, String> tree_my_dst_ = new TreeMap<String, String>();
	public volatile TreeMap<String, String> tree_my_dst_ = new TreeMap<String, String>();
	public volatile TreeMap<String, String> tree_my_dst_ = new TreeMap<String, String>();
	public volatile TreeMap<String, String> tree_my_dst_ = new TreeMap<String, String>();
	public volatile TreeMap<String, String> tree_my_dst_ = new TreeMap<String, String>();
	public volatile TreeMap<String, String> tree_my_dst_ = new TreeMap<String, String>();*/
	
	public static volatile boolean SANITIZE_MAC = false;
	
	public volatile Node_Map_Details node_map_details = null;
	
	public volatile GEO_Location geo = null;
	
	public volatile boolean is_ipv4 = false;
	
	public volatile int unique_domain_name_requests = 0;
	
	/**e.g. www.excite.com, https://excite.com, www.excite.com/123.exe will all be treated as the domain_name excite.com*/
	public volatile String trimmed_domain_name_request = "";
	public volatile String trimmed_http_full_uri_request = "";
	public volatile String trimmed_http_request = "";
	public volatile String trimmed_http_referer = "";
	public volatile String trimmed_http_host_virtual = "";
	public volatile String last_http_request = "";
	public volatile String protocol_summary = "", value = "", found_value = null, packet_statistics = "";
	public volatile String data_view_summary = "";
	public volatile int address_length = 0;
	public volatile String normalized_value = "";
	public volatile String summary = "";
	public volatile String domain_name = "";
	
	public volatile String src_mac = "";
	public volatile String src_ip = "";
	
	public volatile String packet_version = "";
	public volatile String packet_sensor_name = "";
	public volatile String packet_interface_name = "";
	public volatile String packet_frame_time = ""; 
	public volatile String packet_ip_protocol_designation_number = ""; 
	public volatile String packet_src_mac = ""; 
	public volatile String packet_src_ip = ""; 
	
	/**Holds either the tcp or udp last port received*/
	public volatile String packet_src_port = "";
	public volatile String packet_src_port_tcp = ""; 
	public volatile String packet_src_port_udp = ""; 
	public volatile String packet_protocol = ""; 
	public volatile String packet_dst_mac = ""; 
	public volatile String packet_dst_ip = ""; 
	
	/**Holds either the tcp or udp last port received*/
	public volatile String packet_dst_port = "";
	public volatile String packet_dst_port_tcp = ""; 
	public volatile String packet_dst_port_udp = ""; 
	
	/**Based on the last port set: either UDP or TCP, this holds the last transmission type: TCP or UDP*/
	public volatile String packet_transmission_type = "";
	
	public volatile String packet_dns_query = ""; 
	public volatile String packet_http_referer = ""; 
	public volatile String packet_http_request_full_uri = ""; 
	public volatile String packet_http_request = ""; 
	public volatile String packet_http_cookie = ""; 
	public volatile String packet_details = "";
	public volatile String packet_virtual_host = "";
	public volatile String packet_user_agent = "";
	
	public volatile String first_frame_time = "";
	public volatile String last_frame_time = "";
	
	public volatile String alert_indicator = " ";
	
	public volatile boolean is_private_non_routable_ip = false;
	
	public volatile Resolution resolution_my_source_address = null;
	
	/**Stores all protocols that we have encountered so far, e.g. FTP, TCP, HTTP, FTP, etc*/
	public static volatile TreeMap<String, String> tree_protocol_header_names = new TreeMap<String, String>();
	
	/**snapshot in time to accumulate how many packets we've intercepted at a given time interval until it's reset to start over*/
	//public static volatile TreeMap<String, Integer> tree_snapshot_packet_count = new TreeMap<String, Integer>();	
	//public static volatile TreeMap<String, Integer> tree_snapshot_packet_count_OVERFLOW = new TreeMap<String, Integer>();
	public static volatile TreeMap<String, Tuple> tree_snapshot_packet_count = new TreeMap<String, Tuple>();	
	public static volatile TreeMap<String, Tuple> tree_snapshot_packet_count_OVERFLOW = new TreeMap<String, Tuple>();
	
	/**E.G. HTTP - 206 packets, FTP - 98 packets, ETC*/
	public volatile TreeMap<String, Integer> tree_packet_count = new TreeMap<String, Integer>();
	
	public volatile TreeMap<String, Integer> tree_packet_count_OVERFLOW = new TreeMap<String, Integer>();
	
	public volatile String [] jtable_row = null;
	public volatile int index = 4;
	
	/**Tree. The key is the specific signature matched. The Value is the packet summary*/
	public volatile TreeMap <String, String> ALERT_DATABASE = new TreeMap<String, String>();
	
	public volatile TreeMap<String, Resolution> included_node = new TreeMap<String, Resolution>() ;
	
	/**to indicate if the worker thread need to update the gui if this is the selected node to monitor*/
	public volatile boolean updated_packet_count = true;
	
	public volatile String application_key = "";
	
	public volatile String oui = "";
	public volatile String mac_stripped = "";
	public volatile String mac_sanitized = "";
	public volatile Node_OUI OUI = null;

	public static volatile boolean update_cookies_needed = false;
	
	public static volatile LinkedList<Node_Map_Details> list_map_details = new LinkedList<Node_Map_Details>();
	
	
	public static volatile Node_Map_Details map_detail_domain_ip_request = null;
	public static volatile LinkedList<Node_Map_Details> list_dst_ip_and_domain_requests_geo_nodes = new LinkedList<Node_Map_Details>();
	
	public volatile boolean ALERT = false;
	
	public SOURCE(String SOURCE_IP, String SOURCE_MAC)
	{
		try
		{
			if(SOURCE_IP != null)
			{
				src_ip = SOURCE_IP.trim();
				this.address_length = src_ip.length();
			}		
			
			if(SOURCE_MAC != null)
			{
				src_mac = SOURCE_MAC.trim();
				this.mac_stripped = strip_MAC(src_mac);			
				
				try
				{
					if(mac_stripped.length() < 7)
						mac_sanitized = mac_stripped;
					else
						mac_sanitized = mac_stripped.substring(0, 7);
				}
				catch(Exception e){}
				
					
				update_oui(mac_stripped);
			}
			
			this.is_private_non_routable_ip = this.is_private_non_routable_ip(SOURCE_IP);
			
			//determine if we're to nmap this private host
			if(this.is_private_non_routable_ip && NMap.NMAP_ENABLED)
			{
				NMap nmap = new NMap(this, SOURCE_IP);
			}
			
			if(!TREE_SOURCE_NODES.containsKey(src_ip))
			{
				TREE_SOURCE_NODES.put(src_ip, this);
				
				sop("New source node detected and added to system!");
				
				if(!this.is_private_non_routable_ip)
					request_to_resolve(src_ip);
			}
			
			if(!tree_source_nodes_MAC.containsKey(src_mac))
			{
				tree_source_nodes_MAC.put(src_mac, this);
			}
			
			
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "Constructor - 1", e);
		}
	}
	
	public boolean update_oui(String stripped_mac)
	{
		try
		{
			oui = "";

			try	{	OUI = Node_OUI.getMAC_OUI(stripped_mac);	}	catch(Exception e){}
			
			if(OUI == null)
				return false;

			oui = OUI.COMPANY;

			try
			{
				if(!Node_OUI.tree_oui_in_use.containsKey(OUI.MAC_STRIPPED.trim()))
					Node_OUI.tree_oui_in_use.put(OUI.MAC_STRIPPED.trim(), OUI);
			}
			catch(Exception e){}	
			
			OUI.link_device(this);

			

			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "update_mac", e);
		}

		return false;
	}
	
	public boolean request_to_resolve(String request)
	{
		try
		{
			if(request == null || request.trim().equals(""))
				return false;
			
			request = request.toLowerCase().trim();
									
			sop("Sending resolution for [" + request + "]");
			
			//new node, request excalibur resolve this address
			for(Whois_IDS_ResolutionRequest_ThdSocket skt : Whois_IDS_ResolutionRequest_ThdSocket.ALL_CONNECTIONS)
			{
				try
				{
					skt.send(request);
				}
				catch(Exception e)
				{
					continue;
				}
			}
			
			//send this object back as one we'll update when the resolution data comes in
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "request_to_resolve", e, true);
		}
		
		return false;
	}
	
	
	public boolean set_version(String value) 
	{
		try 
		{  
			if(value == null)
				return false;
			
			value = value.trim();
			
			if(value.trim().equals(""))
				return false;
			
			packet_version = value;
			
			//do nothing with this one here...
			

			
			/*this.normalized_value = value.toLowerCase().trim();
			
			if(!Artifact.tree_artifact_.containsKey(normalized_value))
			{
				Artifact artifact = new Artifact(normalized_value, "", this, Artifact.tree_artifact_);
			}*/
			
			
			
			return true;
		} 
		catch(Exception e){} 
		
		return false;
		
	} 
	
	
	public boolean set_sensor_name(String value) 
	{
		try 
		{  
			if(value == null)
				return false;
			
			value = value.trim();
			
			if(value.trim().equals(""))
				return false;
			
			packet_sensor_name = value;
			
			this.normalized_value = value.toLowerCase().trim();
			
			/*if(!Artifact.tree_artifact_.containsKey(normalized_value))
			{
				Artifact artifact = new Artifact(normalized_value, "", this, Artifact.tree_artifact_);
			}*/
			
			
			
			
			
			return true;
		} 
		catch(Exception e){} 
		
		return false;
		
	} 
	
	public boolean set_interface_name(String value) 
	{
		try 
		{  
			if(value == null)
				return false;
			
			value = value.trim();
			
			if(value.trim().equals(""))
				return false;
			
			packet_interface_name = value;
			
			/*this.normalized_value = value.toLowerCase().trim();
			
			if(!Artifact.tree_artifact_.containsKey(normalized_value))
			{
				Artifact artifact = new Artifact(normalized_value, "", this, Artifact.tree_artifact_);
			}*/
			
			
			
			
			
			
			return true;
		} 
		catch(Exception e){} 
		
		return false;
		
	} 
	
	public boolean set_frame_time(String value) 
	{
		try 
		{  
			if(value == null)
				return false;
			
			value = value.trim();
			
			if(value.trim().equals(""))
				return false;
			
			packet_frame_time = value;
			
			if(this.first_frame_time == null || this.first_frame_time.equals(""))
				first_frame_time = packet_frame_time;
			
			last_frame_time = packet_frame_time;	
			
			this.normalized_value = value.toLowerCase().trim();
			
			/*if(!Artifact.tree_artifact_.containsKey(normalized_value))
			{
				Artifact artifact = new Artifact(normalized_value, "", this, Artifact.tree_artifact_);
			}*/
			
					
			
			return true;
		} 
		catch(Exception e){} 
		
		return false;
		
	} 
	
	/**
	 * this is the designation number
	 * @param value
	 * @return
	 */
	public boolean set_ip_protocol(String value) 
	{
		try 
		{  
			if(value == null)
				return false;
			
			value = value.trim();
			
			if(value.trim().equals(""))
				return false;
			
			packet_ip_protocol_designation_number = value;
			
			/*this.normalized_value = value.toLowerCase().trim();
			
			if(!Artifact.tree_artifact_.containsKey(normalized_value))
			{
				Artifact artifact = new Artifact(normalized_value, "", this, Artifact.tree_artifact_);
			}*/
			
			
			
			
			
			
			return true;
		} 
		catch(Exception e){} 
		
		return false;
		
	} 
	
	
	
	
	
	
	
	
	
	public boolean set_src_mac(String value) 
	{
		try 
		{  
			if(value == null)
				return false;
			
			value = value.trim();
			
			if(value.trim().equals(""))
				return false;
			
			packet_src_mac = value;
			
			if(this.src_mac == null || this.src_mac.equals(""))
				src_mac = packet_src_mac;
			

			
			/*this.normalized_value = value.toLowerCase().trim();
			
			if(!Artifact.tree_artifact_.containsKey(normalized_value))
			{
				Artifact artifact = new Artifact(normalized_value, "", this, Artifact.tree_artifact_);
			}*/
			
			
			
			
			return true;
		} 
		catch(Exception e){} 
		
		return false;
		
	} 
	
	
	
	
	public boolean set_src_ip(String value) 
	{
		try 
		{  
			if(value == null)
				return false;
			
			value = value.trim();
			
			if(value.trim().equals(""))
				return false;
			
			packet_src_ip = value;
			
			if(this.src_ip == null || this.src_ip.equals(""))
				src_ip = packet_src_ip;
			

			
			/*this.normalized_value = value.toLowerCase().trim();
			
			if(!Artifact.tree_artifact_.containsKey(normalized_value))
			{
				Artifact artifact = new Artifact(normalized_value, "", this, Artifact.tree_artifact_);
			}*/
			
			
			
			
			return true;
		} 
		catch(Exception e){} 
		
		return false;
		
	} 
	
	
	
	
	public boolean set_src_port_tcp(String value) 
	{
		try 
		{  
			if(value == null)
				return false;
			
			value = value.trim();
			
			if(value.trim().equals(""))
				return false;
			
			packet_src_port_tcp = value;
			
			/*this.normalized_value = value.toLowerCase().trim();
			
			if(!Artifact.tree_artifact_.containsKey(normalized_value))
			{
				Artifact artifact = new Artifact(normalized_value, "", this, Artifact.tree_artifact_);
			}*/
			
			
			
			
			
			return true;
		} 
		catch(Exception e){} 
		
		return false;
		
	} 
	
	
	
	
	public boolean set_src_port_udp(String value) 
	{
		try 
		{  
			if(value == null)
				return false;
			
			value = value.trim();
			
			if(value.trim().equals(""))
				return false;
			
			packet_src_port_udp = value;
			
			/*this.normalized_value = value.toLowerCase().trim();
			
			if(!Artifact.tree_artifact_.containsKey(normalized_value))
			{
				Artifact artifact = new Artifact(normalized_value, "", this, Artifact.tree_artifact_);
			}*/
			
			
			
			
			return true;
		} 
		catch(Exception e){} 
		
		return false;
		
	} 
	
	
	
	
	public boolean set_protocol(String value) 
	{
		
		try 
		{  
			if(value == null)
				return false;
			
			value = value.trim();
			
			if(value.trim().equals(""))
				return false;
			
			packet_protocol = value;
			
			this.normalized_value = value.toLowerCase().trim();
			
			if(!Artifact.tree_artifact_protocol.containsKey(normalized_value))
			{
				Artifact artifact = new Artifact(normalized_value, "protocol", this, Artifact.tree_artifact_protocol);
			}
			
			update_protocol_packet(value);
			
			return true;
		} 
		catch(Exception e){} 
		
		return false;
		
	} 
	
	
	
	public boolean set_dst_mac(String value) 
	{
		try 
		{  
			if(value == null)
				return false;
			
			value = value.trim();
			
			if(value.trim().equals(""))
				return false;
			
			packet_dst_mac = value;
			
			this.normalized_value = value.toLowerCase().trim();
			
			if(!Artifact.tree_artifact_dst_mac.containsKey(normalized_value))
			{
				Artifact artifact = new Artifact(normalized_value, "dst_mac", this, Artifact.tree_artifact_dst_mac);
			}
			
			//
			//link to self
			//
			if(!tree_my_dst_macs.containsKey(normalized_value))
				tree_my_dst_macs.put(normalized_value, null);
			
			
			return true;
		} 
		catch(Exception e){} 
		
		return false;
		
	} 
	
	
	
	
	public boolean set_dst_ip(String value, Resolution resolution_search, String dst_port, String protocol, String user_agent) 
	{
		try 
		{  
			if(value == null)
				return false;
			
			value = value.trim();
			
			if(value.trim().equals(""))
				return false;
			
			packet_dst_ip = value;
			
			this.normalized_value = value.toLowerCase().trim();
			
			if(!Artifact.tree_artifact_dst_ip.containsKey(normalized_value))
			{
				Artifact artifact = new Artifact(normalized_value, "dst_ip", this, Artifact.tree_artifact_dst_ip);
			}
			
			//
			//link to self
			//
			//resolution_search = null;
			
			if(resolution_search == null && Resolution.TREE_RESOURCE.containsKey(normalized_value))
				resolution_search = Resolution.TREE_RESOURCE.get(normalized_value);
			
			//determine if we've seen the resolution before
			/*if(Resolution.tree_resolution.containsKey(normalized_value))
				resolution_search = Resolution.tree_resolution.get(normalized_value);
			else if(Resolution.tree_unresolved_request.containsKey(normalized_value))
				resolution_search = Resolution.tree_unresolved_request.get(normalized_value);*/
			
			//check if we have a resolution
			if(resolution_search == null)
				resolution_search = new Resolution(normalized_value, this);
			else
				resolution_search.link_requestor(this);
						
			
			
			if(!tree_my_dst_ip.containsKey(normalized_value))
				tree_my_dst_ip.put(normalized_value, resolution_search);
			
			//
			//OMIT DNS FOR THE APPLICATION CATEGORIZATION
			//
			if(protocol == null || protocol.trim().equalsIgnoreCase("dns"))
				return true;
			
			//
			//determine if we have a new application
			//
			if(this.is_private_non_routable_ip && dst_port != null && !dst_port.trim().equals(""))
			{
				//create a new application if not exists and pass in the resource as itself
				application_key = normalized_value + ":" + dst_port;
				Application application = null;
				
				if(Application.TREE_APPLICATION.containsKey(application_key))
					application = Application.TREE_APPLICATION.get(application_key);
				if(application == null)
					application = new Application(application_key, normalized_value, dst_port, protocol, resolution_search, user_agent);
				
				application.link_source(this);
			}
			
			
			
			return true;
		} 
		catch(Exception e){} 
		
		return false;
		
	} 
	
	
	
	
	public boolean set_dst_port_tcp(String value) 
	{
		try 
		{  
			if(value == null)
				return false;
			
			value = value.trim();
			
			if(value.trim().equals(""))
				return false;
			
			packet_dst_port_tcp = value;
			
			/*this.normalized_value = value.toLowerCase().trim();
			
			if(!Artifact.tree_artifact_.containsKey(normalized_value))
			{
				Artifact artifact = new Artifact(normalized_value, "", this, Artifact.tree_artifact_);
			}*/
			
			
			
			
			return true;
		} 
		catch(Exception e){} 
		
		return false;
		
	} 
	
	
	
	
	public boolean set_dst_port_udp(String value) 
	{
		
		try 
		{  
			if(value == null)
				return false;
			
			value = value.trim();
			
			if(value.trim().equals(""))
				return false;
			
			packet_dst_port_udp = value;
			
			/*this.normalized_value = value.toLowerCase().trim();
			
			if(!Artifact.tree_artifact_.containsKey(normalized_value))
			{
				Artifact artifact = new Artifact(normalized_value, "", this, Artifact.tree_artifact_);
			}*/
			
			
			
			
			return true;
		} 
		catch(Exception e){} 
		
		return false;
		
	} 
	
	
	
	public boolean set_dns_query(String value, Resolution resolution_search) 	
	{
		try 
		{  
			if(value == null)
				return false;
			
			value = value.trim();
			
			if(value.trim().equals(""))
				return false;
			
			packet_dns_query = value;
			
			this.normalized_value = value.toLowerCase().trim();
			
			if(this.trimmed_domain_name_request == null || this.trimmed_domain_name_request.equals("") || !trimmed_domain_name_request.contains("."))
				this.trimmed_domain_name_request = normalized_value;
			
			if(!Artifact.tree_artifact_domain_name_request_trimmed.containsKey(trimmed_domain_name_request))
			{
				Artifact artifact = new Artifact(trimmed_domain_name_request, "domain_name_request", this, Artifact.tree_artifact_domain_name_request_trimmed);
			}
			
			//
			//link to self
			//
			//resolution_search = null;
			
			//determine if we've seen the resolution before
			if(resolution_search == null && Resolution.TREE_RESOURCE.containsKey(trimmed_domain_name_request))
				resolution_search = Resolution.TREE_RESOURCE.get(trimmed_domain_name_request);
			
			/*if(Resolution.tree_resolution.containsKey(trimmed_domain_name_request))
				resolution_search = Resolution.tree_resolution.get(trimmed_domain_name_request);
			else if(Resolution.tree_unresolved_request.containsKey(trimmed_domain_name_request))
				resolution_search = Resolution.tree_unresolved_request.get(trimmed_domain_name_request);*/
			
			//check if we have a resolution
			if(resolution_search == null)
				resolution_search = new Resolution(trimmed_domain_name_request, this);
			else
				resolution_search.link_requestor(this);
			
			
			if(!tree_my_domain_name_requests.containsKey(trimmed_domain_name_request))
				tree_my_domain_name_requests.put(trimmed_domain_name_request, resolution_search);
			
			//
			//now repeat the process for the full dns query in case of maps.google.com
			//
			if(Resolution.TREE_RESOURCE.containsKey(normalized_value))
				resolution_search = Resolution.TREE_RESOURCE.get(normalized_value);	
			else
				resolution_search = new Resolution(normalized_value, this);
			
			//check if we have a resolution
			if(resolution_search == null)
				resolution_search = new Resolution(normalized_value, this);
			else
				resolution_search.link_requestor(this);
			
			
			if(!tree_my_domain_name_requests.containsKey(normalized_value))
				tree_my_domain_name_requests.put(normalized_value, resolution_search);
			
			return true;
		} 
		catch(Exception e){} 
		
		return false;
		
	} 
	
	
	
	
	public boolean set_http_referer(String value, Resolution resolution_search) 
	{
		try 
		{  
			if(value == null)
				return false;
			
			value = value.trim();
			
			if(value.trim().equals(""))
				return false;
			
			packet_http_referer = value;
			
			normalized_value = value.toLowerCase().trim();
			
			if(this.trimmed_http_referer == null || this.trimmed_http_referer.equals("") || !trimmed_http_referer.contains("."))
				this.trimmed_http_referer = normalized_value;
			
			if(!Artifact.tree_artifact_http_referer.containsKey(trimmed_http_referer))
			{
				Artifact artifact = new Artifact(trimmed_http_referer, "http_referer", this, Artifact.tree_artifact_http_referer);
			}
			
			//
			//link to self
			//
			//resolution_search = null;
			
			//determine if we've seen the resolution before
			if(resolution_search == null && Resolution.TREE_RESOURCE.containsKey(trimmed_http_referer))
				resolution_search = Resolution.TREE_RESOURCE.get(trimmed_http_referer);
			/*if(Resolution.tree_resolution.containsKey(trimmed_http_referer))
				resolution_search = Resolution.tree_resolution.get(trimmed_http_referer);
			else if(Resolution.tree_unresolved_request.containsKey(trimmed_http_referer))
				resolution_search = Resolution.tree_unresolved_request.get(trimmed_http_referer);*/
			
			//check if we have a resolution
			if(resolution_search == null)
				resolution_search = new Resolution(trimmed_http_referer, this);
			else
				resolution_search.link_requestor(this);
			
			
			if(!tree_my_http_referer.containsKey(trimmed_http_referer))
				this.tree_my_http_referer.put(trimmed_http_referer, resolution_search);
			
			
			
			
			
			
			return true;
		} 
		catch(Exception e){} 
		
		return false;
		
	} 
	
	
	
	
	public boolean set_http_request_full_uri(String value, Resolution resolution_search) 
	{
		try 
		{  if(value == null)
			return false;
		
		value = value.trim();
		
		if(value.trim().equals(""))
			return false;
		
		
		packet_http_request_full_uri = value;
		
		this.normalized_value = value.toLowerCase().trim();
		
		
		
		if(this.trimmed_http_full_uri_request == null || this.trimmed_http_full_uri_request.equals("") || !trimmed_http_full_uri_request.contains("."))
			this.trimmed_http_full_uri_request = normalized_value;
		
		if(!Artifact.tree_artifact_domain_name_request_trimmed.containsKey(trimmed_http_full_uri_request))
		{
			Artifact artifact = new Artifact(trimmed_http_full_uri_request, "domain_name_request", this, Artifact.tree_artifact_domain_name_request_trimmed);
		}
		
		//
		//link to self
		//
		//resolution_search = null;
		
		//determine if we've seen the resolution before
		if(resolution_search == null && Resolution.TREE_RESOURCE.containsKey(trimmed_http_full_uri_request))
			resolution_search = Resolution.TREE_RESOURCE.get(trimmed_http_full_uri_request);
		/*if(Resolution.tree_resolution.containsKey(trimmed_http_full_uri_request))
			resolution_search = Resolution.tree_resolution.get(trimmed_http_full_uri_request);
		else if(Resolution.tree_unresolved_request.containsKey(trimmed_http_full_uri_request))
			resolution_search = Resolution.tree_unresolved_request.get(trimmed_http_full_uri_request);*/
		
		//check if we have a resolution
		if(resolution_search == null)
			resolution_search = new Resolution(trimmed_http_full_uri_request, this);
		else
			resolution_search.link_requestor(this);
		
		
		
		if(!this.tree_my_domain_name_requests.containsKey(trimmed_http_full_uri_request))
			this.tree_my_domain_name_requests.put(trimmed_http_full_uri_request, resolution_search);
		
		
		
		
		return true;
		} 
		catch(Exception e){} 
		
		return false;
		
	} 
	
	/**
	 * http.host is like the virtual host. as in a single server ip address may host multiple aliases or domain_names, this isthe host being requested at the server
	 * @param value
	 * @param resolution_search
	 * @return
	 */
	public boolean set_http_host(String value, Resolution resolution_search) 
	{
		try 
		{  
			if(value == null)
				return false;
			
			value = value.trim();
			
			if(value.trim().equals(""))
				return false;
			
			packet_virtual_host = value;
			
			normalized_value = value.toLowerCase().trim();
			
			if(this.trimmed_http_host_virtual == null || this.trimmed_http_host_virtual.equals("") || !trimmed_http_host_virtual.contains("."))
				this.trimmed_http_host_virtual = normalized_value;
			
			if(!Artifact.tree_artifact_http_host_virtual.containsKey(trimmed_http_host_virtual))
			{
				Artifact artifact = new Artifact(trimmed_http_host_virtual, "http_host", this, Artifact.tree_artifact_http_host_virtual);
			}
			
			//
			//link to self
			//
			//resolution_search = null;
			
			//determine if we've seen the resolution before
			if(resolution_search == null && Resolution.TREE_RESOURCE.containsKey(trimmed_http_host_virtual))
				resolution_search = Resolution.TREE_RESOURCE.get(trimmed_http_host_virtual);
		
			
			//check if we have a resolution
			if(resolution_search == null)
				resolution_search = new Resolution(trimmed_http_host_virtual, this);
			else
				resolution_search.link_requestor(this);
			
			
			if(!tree_my_http_host_virtual.containsKey(trimmed_http_host_virtual))
				this.tree_my_http_host_virtual.put(trimmed_http_host_virtual, resolution_search);
			
			
			
			
			
			
			
			return true;
		} 
		catch(Exception e){} 
		
		return false;
		
	} 
	
	/**this is the designation number*/
	public boolean set_http_request(String value) 
	{
		try 
		{  
			if(value == null)
				return false;
			
			value = value.trim();
			
			if(value.trim().equals(""))
				return false;
			
			packet_http_request = value;
			
			/*if(this.trimmed_http_request == null || this.trimmed_http_request.equals(""))
				this.trimmed_http_request = normalized_value;
			
			if(!Artifact.tree_artifact_domain_name_request_trimmed.containsKey(trimmed_http_request))
			{
				Artifact artifact = new Artifact(trimmed_http_request, "domain_name_request", this, Artifact.tree_artifact_domain_name_request_trimmed);
			}
			
			//
			//link to self
			//
			if(!this.tree_my_domain_name_requests.containsKey(trimmed_http_request))
				this.tree_my_domain_name_requests.put(trimmed_http_request, null);
			*/
			
			
			
			return true;
		} 
		catch(Exception e){} 
		
		return false;
		
	} 
	
	public boolean set_user_agent(String value, User_Agent user_agent) 
	{
		try 
		{  
			if(value == null)
				return false;
			
			value = value.trim();
			
			if(value.trim().equals(""))
				return false;
			
			packet_user_agent = value;
			
			normalized_value = value.toLowerCase().trim();
					
			if(!Artifact.tree_artifact_user_agent.containsKey(normalized_value))
			{
				Artifact artifact = new Artifact(normalized_value, "user_agent", this, Artifact.tree_artifact_user_agent);
			}
			
			//
			//link to self
			//			
			
			//determine if we've seen the resolution before
			if(user_agent == null && User_Agent.TREE_USER_AGENT.containsKey(normalized_value))
				user_agent = User_Agent.TREE_USER_AGENT.get(normalized_value);
		
			
			//check if we have a resolution
			if(user_agent == null)
				user_agent = new User_Agent(normalized_value, this);
			else
				user_agent.link_requestor(this);
			
			
			if(!this.tree_my_user_agent.containsKey(normalized_value))
				this.tree_my_user_agent.put(normalized_value, user_agent);														
			
			//driver.jop("user agent: " + normalized_value + "\n" + user_agent.user_agent + "\n" + tree_my_user_agent.size());
			
			return true;
		} 
		catch(Exception e){} 
		
		return false;
		
	} 
	
	
	public boolean set_http_cookie(String value, String full_uri_request) 
	{
		try 
		{  
			if(value == null)
				return false;
			
			value = value.trim();
			
			if(value.trim().equals(""))
				return false;
			
			packet_http_cookie = value;
			
			//this.normalized_value = value.toLowerCase().trim();
			this.normalized_value = value.trim();
			
			if(!Artifact.tree_artifact_cookie.containsKey(normalized_value))
			{
				Artifact artifact = new Artifact(normalized_value, "cookie", this, Artifact.tree_artifact_cookie);
			}
			
			//
			//update last http request
			//
			last_http_request = full_uri_request;
			
			if(last_http_request == null || last_http_request.trim().equals(""))
			{
				if(packet_dns_query != null && !packet_dns_query.trim().equals(""))
					last_http_request = packet_dns_query;
			}
			
			//
			//link to self
			//
			if(!tree_my_cookie.containsKey(normalized_value + ", " + last_http_request))
			{
				tree_my_cookie.put(normalized_value + ", " + last_http_request, null);
				
				update_cookies_needed = true;
			}
			/*else if(!tree_my_cookie.containsKey(normalized_value))
				tree_my_cookie.put(normalized_value, null);*/
										
			
			
			return true;
		} 
		catch(Exception e){} 
		
		return false;
		
	} 
	
	
	
	
	public boolean set_details(String value) 
	{
		try 
		{  
			if(value == null)
				return false;
			
			value = value.trim();
			
			if(value.trim().equals(""))
				return false;
			
			packet_details = value;
			
			/*this.normalized_value = value.toLowerCase().trim();
			
			if(!Artifact.tree_artifact_.containsKey(normalized_value))
			{
				Artifact artifact = new Artifact(normalized_value, "", this, Artifact.tree_artifact_);
			}*/
			
			
			
			return true;
		} 
		catch(Exception e){} 
		
		return false;
		
	} 
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	public boolean sop(String line)
	{
		try
		{
			if(line == null || line.trim().equals(""))
				return false;
			
			line = line.trim();
			
			if(Driver.parser_output_enabled)
			{
				driver.sop(this.src_ip + "-\t [" + this.src_mac + "] --> " + line);
			}
			
			return true;
		}
		
		catch(Exception e)
		{
			driver.eop(myClassName, "sop", e);
		}
		
		return false;
	}
	
	
	public String get_protocol_summary(String delimiter, boolean include_protocol_header)
	{
		try
		{
			protocol_summary = src_ip + delimiter + this.src_mac + delimiter + this.first_frame_time + delimiter + this.last_frame_time + delimiter;
			
			for(String proto : SOURCE.tree_protocol_header_names.values())
			{
				if(this.tree_packet_count.containsKey(proto))
					value = "" + tree_packet_count.get(proto);
				else
					value = "0";
				
				if(include_protocol_header)					
					protocol_summary = protocol_summary + proto + ": " + value + delimiter;
				else
					protocol_summary = protocol_summary + value + delimiter;						
			}
			
			return protocol_summary;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "get_protocol_summary", e);
		}
		
		return this.src_ip + " -- ";
	}
	
	
	
	public String [] get_jtable_row_summary(String delimiter, boolean include_protocol_header)
	{
		try
		{
			if(SOURCE.tree_protocol_header_names == null || SOURCE.tree_protocol_header_names.isEmpty())
			{
				jtable_row = new String[]{this.src_ip, this.src_mac, this.first_frame_time, this.last_frame_time	};
				return jtable_row;
			}
			
			jtable_row = new String[12 + SOURCE.tree_protocol_header_names.size()];
			jtable_row[0] = this.src_ip;
			jtable_row[1] =	this.src_mac;
			jtable_row[2] =	this.oui;
			
			//update the unique domain_requsts first
			this.get_domain_name_requests("Domain Name Requests:", this.tree_my_domain_name_requests);
			jtable_row[3] =	"" + unique_domain_name_requests;
			/*if(this.tree_my_domain_name_requests != null)
				jtable_row[3] =	""+this.tree_my_domain_name_requests.size();
			else
				jtable_row[3] =	"0";*/
									
			//RESOURCES
			if(this.tree_my_dst_ip != null)
				jtable_row[4] =	""+this.tree_my_dst_ip.size();
			else
				jtable_row[4] =	"0";
			
			if(this.tree_my_cookie != null)
				jtable_row[5] =	""+this.tree_my_cookie.size();
			else
				jtable_row[5] =	"0";
			
			if(this.tree_my_http_host_virtual != null)
				jtable_row[6] =	""+this.tree_my_http_host_virtual.size();
			else
				jtable_row[6] =	"0";
			
			if(this.tree_my_http_referer != null)
				jtable_row[7] =	""+this.tree_my_http_referer.size();
			else
				jtable_row[7] =	"0";
						
			
			jtable_row[8] = this.alert_indicator;
			jtable_row[9] = this.first_frame_time;
			jtable_row[10] = this.last_frame_time;
			jtable_row[11] =	""+this.is_private_non_routable_ip;
			
			protocol_summary = src_ip + delimiter + this.src_mac + delimiter + this.alert_indicator + delimiter + this.first_frame_time + delimiter + this.last_frame_time + delimiter;
			
			index = 12;
			for(String proto : SOURCE.tree_protocol_header_names.values())
			{
				if(this.tree_packet_count.containsKey(proto))
					value = "" + tree_packet_count.get(proto);
				else
					value = "0";
				
				if(include_protocol_header)					
				{
					protocol_summary = protocol_summary + proto + ": " + value + delimiter;
					
					jtable_row[index++] = proto + ": " + value;
				}
				else
				{
					protocol_summary = protocol_summary + value + delimiter;
					
					jtable_row[index++] = value;
				}
			}
			
			return jtable_row;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "get_jtable_row_summary", e);
		}
		
		return jtable_row;
	}
	
	/**
	 * e.g. key == http_request_full_uri
	 * 		specification == "malware.com/123.exe"
	 * 
	 * specification can be null, if so, then what ever key is found matching the specification will be returned
	 * 
	 * but only if identification value is not null, will we perform the regex searching for it. 
	 * @param key
	 * @param specification
	 * @return
	 */
	public String get(String key, String specification)
	{
		try
		{
			if(key == null || key.trim().equals(""))
				return null;
			
			found_value = null;			

			//convert to upper case
			key = key.toLowerCase().trim();
			
			if(key.equalsIgnoreCase("source") || key.equalsIgnoreCase("src_ip"))
				found_value =  src_ip;
			
			else if(key.equalsIgnoreCase("mac") || key.equalsIgnoreCase("src_mac"))
				found_value =  src_mac;
			
			else if(key.startsWith("first") && (key.contains("time") || (key.contains("contact"))))
				found_value =  first_frame_time;
			
			else if(key.startsWith("last") && (key.contains("time") || (key.contains("contact"))))
				found_value =  last_frame_time;
			
			if(key.equalsIgnoreCase("version"))
				found_value =  this.packet_version;
			
			else if((key.startsWith("source") || key.startsWith("src")) && key.contains("port"))
				found_value =  this.packet_src_port;						
			
			else if((key.startsWith("dest") || key.startsWith("destination") || key.startsWith("dst")) && key.contains("port"))
				found_value =  this.packet_dst_port;
			
			else if((key.startsWith("dest") || key.startsWith("destination") || key.startsWith("dst")) && key.contains("ip"))
				found_value =  this.packet_dst_ip;
			
			else if((key.startsWith("dest") || key.startsWith("destination") || key.startsWith("dst")) && key.contains("mac"))
				found_value =  this.packet_dst_mac;
			
			else if(key.startsWith("transmission") && key.contains("type"))
				found_value =  this.packet_transmission_type;
			
			else if(key.startsWith("sensor"))
				found_value =  this.packet_sensor_name;
			
			else if(key.startsWith("interface"))
				found_value =  this.packet_interface_name;
			
			else if(key.startsWith("frame_time") || key.startsWith("packet_time"))
				found_value =  this.packet_frame_time;
			
			else if(key.equalsIgnoreCase("protocol"))
				found_value =  packet_protocol;
			
			else if(key.equalsIgnoreCase("ip_protocol"))
				found_value =  this.packet_ip_protocol_designation_number;
			
			else if(key.startsWith("ip_protocol") || key.equalsIgnoreCase("proto"))
				found_value =  this.packet_frame_time;
			
			else if(key.startsWith("dns") && (key.contains("query") || key.contains("name") || key.contains("qry")) )
				found_value =  this.packet_dns_query;			
						
			else if(key.startsWith("http") && (key.contains("refer")))
				found_value =  this.packet_http_referer; 
			
			else if(key.startsWith("private"))
				found_value =  ""+this.is_private_non_routable_ip; 
			 
			else if(key.startsWith("http") && (key.contains("req")) )
			{
				if(packet_http_request_full_uri != null && !packet_http_request_full_uri.trim().equals(""))
					found_value =  this.packet_http_request_full_uri;
				else
					found_value =  packet_http_request;					
			}
			
			else if(key.equalsIgnoreCase("request") )
			{
				if(packet_http_request_full_uri != null && !packet_http_request_full_uri.trim().equals(""))
					found_value =  this.packet_http_request_full_uri;
				else
					found_value =  packet_http_request;					
			}
			
			else if(key.equalsIgnoreCase("uri") )
			{
				if(packet_http_request_full_uri != null && !packet_http_request_full_uri.trim().equals(""))
					found_value =  this.packet_http_request_full_uri;
				else
					found_value =  packet_http_request;					
			}
			
			else if(key.equalsIgnoreCase("url") )
			{
				if(packet_http_request_full_uri != null && !packet_http_request_full_uri.trim().equals(""))
					found_value =  this.packet_http_request_full_uri;
				else
					found_value =  packet_http_request;					
			}
			
			else if(key.startsWith("http") && (key.contains("cookie")))
				found_value =  this.packet_http_referer; 
			 
			else if(key.startsWith("detail"))
				found_value =  this.packet_details; 
			
			
			//otw, check the tree of summary values				
			if(this.tree_packet_count.containsKey(key))
				found_value =  "" + tree_packet_count.get(key);
			
			else if(this.tree_packet_count.containsKey(key.toUpperCase().trim()))
				found_value =  "" + tree_packet_count.get(key.toUpperCase().trim());
			
			//check if we have something to this point
			if(found_value == null)
				return found_value;
			
			//restrict based on the filter value
			if(specification == null || specification.trim().equals(""))
			{
				//return whatever we found
				return found_value;
			}
			
			//check regex
			
			if(specification.equals("*"))
				return found_value;
			
			else if(specification.startsWith("*") && specification.endsWith("*"))
			{				
				if(found_value.toLowerCase().trim().contains(specification.substring(1, specification.length()-1).toLowerCase().trim()))
					return found_value;
			}
			
			else if(specification.startsWith("*"))
			{				
				if(found_value.toLowerCase().trim().endsWith(specification.substring(1).toLowerCase().trim()))
					return found_value;
			}
			
			else if(specification.endsWith("*"))
			{									
				if(found_value.toLowerCase().trim().startsWith(specification.substring(0, specification.length()-1).toLowerCase().trim()))
					return found_value;
			}
			else //equals
			{
				if(found_value.equalsIgnoreCase(specification))
					return found_value;
			}
			
			
			//otw, not found!
			return null;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "get", e);
		}
		
		return null;
	
	}
	/**
	 * specification == *123*, or 192.*, etc
	 * value == 192.168.0.101
	 * @param specification
	 * @param value
	 * @return
	 */
	public String match(String specification, String value)
	{
		try
		{
			found_value = value;
			
			if(specification.equals("*"))
				return found_value;
			
			else if(specification.startsWith("*") && specification.endsWith("*"))
			{				
				if(found_value.toLowerCase().trim().contains(specification.substring(1, specification.length()-1).toLowerCase().trim()))
					return found_value;
			}
			
			else if(specification.startsWith("*"))
			{				
				if(found_value.toLowerCase().trim().endsWith(specification.substring(1).toLowerCase().trim()))
					return found_value;
			}
			
			else if(specification.endsWith("*"))
			{									
				if(found_value.toLowerCase().trim().startsWith(specification.substring(0, specification.length()-1).toLowerCase().trim()))
					return found_value;
			}
			else //equals
			{
				if(found_value.equalsIgnoreCase(specification))
					return found_value;
			}
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "match", e);
		}
		
		return null;
	}
	
	public String getDataViewInformation(String delimiter, boolean include_packet_statistics)
	{
		try
		{
			data_view_summary = "Source Address: " + this.src_ip + "\n";
			address_length = src_ip.length();
			if(include_packet_statistics)
			{
				for(int i = 0; i < address_length+16; i++)
				{
					data_view_summary = data_view_summary + "=";
				}
				
				if(domain_name != null && !domain_name.trim().equals(""))
					data_view_summary = data_view_summary + "\n\nDomain Name:\n============\n" + domain_name;
			}
			
			data_view_summary = data_view_summary + delimiter + delimiter;			
			data_view_summary = data_view_summary + "MAC Address: " + this.src_mac + delimiter;
			
			if(include_packet_statistics)
				data_view_summary = data_view_summary + "==============================" + delimiter + delimiter;
			
			if(oui != null && !oui.trim().equals(""))
			{
				data_view_summary = data_view_summary +  "Device Unique Identifier: " + this.oui + delimiter + delimiter;								
			}
												
			data_view_summary = data_view_summary + "[Most Recent Packet Details] " + delimiter;
			
			if(include_packet_statistics)
				data_view_summary = data_view_summary + "============================" + delimiter + delimiter;
						
			data_view_summary = data_view_summary + "Themis Sensor Name: " + packet_sensor_name + delimiter;
			data_view_summary = data_view_summary + "Interface Captured On: " + packet_interface_name + delimiter;
									
			if(domain_name != null && !domain_name.trim().equals(""))
				data_view_summary = data_view_summary + "Domain Name: " + domain_name + delimiter;
			
			data_view_summary = data_view_summary + "Packet Protocol: " + packet_protocol + delimiter;
			data_view_summary = data_view_summary + "First Packet Received: " + first_frame_time + delimiter;
			data_view_summary = data_view_summary + "Last  Packet Received: " + last_frame_time + delimiter;
			
			data_view_summary = data_view_summary + "Source MAC: " + packet_src_mac + delimiter; 
			data_view_summary = data_view_summary + "Source IP: " + packet_src_ip + delimiter; 			
			data_view_summary = data_view_summary + "Source Port: " + packet_src_port + delimiter;
			
			 
			data_view_summary = data_view_summary + "Destination MAC: " + packet_dst_mac + delimiter; 
			data_view_summary = data_view_summary + "Destination IP: " + packet_dst_ip + delimiter; 
			data_view_summary = data_view_summary + "Destination Port: " + packet_dst_port + delimiter;			
			data_view_summary = data_view_summary + "Packet Type: " + packet_transmission_type + delimiter;
			
			if(packet_dns_query != null && !packet_dns_query.trim().equals(""))
				data_view_summary = data_view_summary + "DNS Query: " + packet_dns_query + delimiter; 
			
			if(packet_http_referer != null && !packet_http_referer.trim().equals(""))				 
				data_view_summary = data_view_summary + "HTTP Referer: " + packet_http_referer + delimiter;
			
			if(packet_http_request_full_uri != null && !packet_http_request_full_uri.trim().equals(""))
				data_view_summary = data_view_summary + "Full URI Request: " + packet_http_request_full_uri + delimiter;
			
			if(packet_http_request != null && !packet_http_request.trim().equals(""))		
				data_view_summary = data_view_summary + "HTTP Request: " + packet_http_request + delimiter;
			
			if(packet_http_cookie != null && !packet_http_cookie.trim().equals(""))
				data_view_summary = data_view_summary + "HTTP Cookie: " + packet_http_cookie + delimiter;
			
			if(packet_details != null && !packet_details.trim().equals(""))	
				data_view_summary = data_view_summary + "Details: " + packet_details + delimiter;
			
			if(this.packet_virtual_host != null && !packet_virtual_host.trim().equals(""))	
				data_view_summary = data_view_summary + "Host (Virtual): " + packet_virtual_host + delimiter;
			
			if(this.packet_user_agent != null && !packet_user_agent.trim().equals(""))	
				data_view_summary = data_view_summary + "User Agent: " + packet_user_agent + delimiter;
			
			//packet statistics
			if(include_packet_statistics)
			{
				//ALERTS:
				if(!ALERT_DATABASE.isEmpty())
				{
					data_view_summary = data_view_summary + delimiter + "ALERTS: " + delimiter + "=======" + delimiter;
					
					for(String alert : ALERT_DATABASE.values())
						data_view_summary = data_view_summary + "Alert Details: " + alert + delimiter;						
				}
				
				
				//PACKETS
				data_view_summary = data_view_summary + delimiter + "Packet Summary: " + delimiter + "===============" + delimiter;
				data_view_summary = data_view_summary + get_specific_packet_statistics(delimiter, true);
				
				//GEO
				if(geo != null)
				{
					data_view_summary = data_view_summary + "\nGEO Location:\n=============\n";
					data_view_summary = data_view_summary + geo.toString("\n") + "\n";
				}
				
				//Specific requests				
				data_view_summary = data_view_summary + delimiter + this.get_destination_ip_details("Destination IP:", tree_my_dst_ip) + "\n";
				data_view_summary = data_view_summary + delimiter + this.get_string_details("Destination MAC:", tree_my_dst_macs) + "\n";
				data_view_summary = data_view_summary + delimiter + this.get_domain_name_requests("Domain Name Requests:", this.tree_my_domain_name_requests) + "\n";
				data_view_summary = data_view_summary + delimiter + this.get_string_details("Hosts (Virtual):", this.tree_my_http_host_virtual) + "\n";
				data_view_summary = data_view_summary + delimiter + this.get_string_details("HTTP Referer:", this.tree_my_http_referer) + "\n";
				data_view_summary = data_view_summary + delimiter + this.get_string_details("Cookies:", this.tree_my_cookie) + "\n";				
				data_view_summary = data_view_summary + delimiter + this.get_user_agent();
				
			}
			
			
			
					 			 			 															
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "getDataViewInformation", e);
		}
		
		return data_view_summary;
	}
	
	public String get_destination_ip_details(String title, TreeMap<String, Resolution> tree)
	{
		try
		{
			summary = "";
			
			if(tree == null || tree.isEmpty())
				return "";
			
			summary = title.trim() + "\n";
			
			address_length = title.length();
			for(int i = 0; i < address_length; i++)
			{
				summary = summary + "=";
			}
				
			summary = summary + "\n";
			
			try	{	included_node.clear();} 	catch(Exception e){included_node = new TreeMap<String, Resolution>();}
			
			for(Resolution resolution : tree.values())
			{
				if(resolution == null)
					continue;
				
				if(included_node.containsValue(resolution))
					continue;
				
				if(included_node.containsKey(resolution.address))
					continue;
				
				included_node.put(resolution.address, resolution);
				
				if(resolution.ALERT)
					summary = summary + "[ALERT] ";
							
				if(resolution.is_private_non_routable_address)
					summary = summary + resolution.address + "\n";
				
				else if(!resolution.internal_ipv4.trim().equals("") && resolution.domain_name != null && !resolution.domain_name.trim().equals("") && !resolution.domain_name.trim().equals(resolution.internal_ipv4))
					summary = summary + resolution.internal_ipv4 + "\t - \t"  + resolution.domain_name + "\n";
				
				else if(resolution.is_ipv4)
					summary = summary + resolution.address + "\n";
			}
			
			
			try	{	included_node.clear();} 	catch(Exception e){included_node = new TreeMap<String, Resolution>();}
			
			return summary;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "get_destination_ip_details", e);
		}
		
		return summary;
	}
	
	public LinkedList<Node_Map_Details> get_linked_list_dst_ip_and_domain_request_geo_nodes(boolean include_header)
	{
		try
		{
			//establish the map details
			try	{	list_dst_ip_and_domain_requests_geo_nodes.clear();}	catch(Exception e){ list_dst_ip_and_domain_requests_geo_nodes = new LinkedList<Node_Map_Details>();}
			
			//iterate through the source node resources...
			if(this.tree_my_dst_ip != null && !this.tree_my_dst_ip.isEmpty())
			{
				for(Resolution resource : tree_my_dst_ip.values())
				{
					if(resource == null)
						continue;
					
					if(resource.geo == null)
						continue;
					
					map_detail_domain_ip_request = resource.get_map_node(include_header);
					
					if(map_detail_domain_ip_request == null)
						continue;									
					
					
					if(!list_dst_ip_and_domain_requests_geo_nodes.contains(map_detail_domain_ip_request))
						list_dst_ip_and_domain_requests_geo_nodes.add(map_detail_domain_ip_request);
							
				}
			}
			
			//iterate through domain name requests
			if(this.tree_my_domain_name_requests != null && !this.tree_my_domain_name_requests.isEmpty())
			{
				for(Resolution resource : tree_my_domain_name_requests.values())
				{
					if(resource == null)
						continue;
					
					if(resource.geo == null)
						continue;
					
					map_detail_domain_ip_request = resource.get_map_node(include_header);
					
					if(map_detail_domain_ip_request == null)
						continue;									
					
					
					if(!list_dst_ip_and_domain_requests_geo_nodes.contains(map_detail_domain_ip_request))
						list_dst_ip_and_domain_requests_geo_nodes.add(map_detail_domain_ip_request);
							
				}
			}
			
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "get_linked_list_dst_ip_and_domain_requests_nodes", e);
		}
		
		return list_dst_ip_and_domain_requests_geo_nodes;
		
	}
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
//	public String get_string_details(String title, TreeMap<String, Resolution> tree)
//	{
//		try
//		{
//			summary = "";
//			
//			if(tree == null || tree.isEmpty())
//				return "";
//			
//			summary = title.trim() + "\n";
//			
//			address_length = title.length();
//			for(int i = 0; i < address_length; i++)
//			{
//				summary = summary + "=";
//			}
//				
//			summary = summary + "\n";
//			
//			try	{	included_node.clear();} 	catch(Exception e){included_node = new TreeMap<String, Resolution>();}
//			
//			for(String key : tree.keySet())
//			{
//				//check if we have a true resolution
//				resolution_search = tree.get(key);
//				
//				if(resolution_search == null)
//					continue;
//				
//				if(included_node.containsKey(key))
//					continue;
//				
//				if(included_node.containsValue(resolution_search))
//					continue;
//				
//				included_node.put(resolution_search.address, resolution_search);								
//				included_node.put(key, resolution_search);
//				
//				if(resolution_search == null)							
//					summary = summary + key + "\n"; //otherwise, just include the key name
//				else
//					summary = summary + resolution_search.getSummaryOverview("\t ") + "\n";
//					
//					
//			}
//			
//			try	{	included_node.clear();} 	catch(Exception e){included_node = new TreeMap<String, Resolution>();}
//			
//			return summary;
//		}
//		catch(Exception e)
//		{
//			driver.eop(myClassName, "get_string_details", e);
//		}
//		
//		return summary;
//	}
	
	public String get_string_details(String title, TreeMap<String, Resolution> tree)
	{
		try
		{
			summary = "";
			
			if(tree == null || tree.isEmpty())
				return "";
			
			summary = title.trim() + "\n";
			
			address_length = title.length();
			for(int i = 0; i < address_length; i++)
			{
				summary = summary + "=";
			}
				
			summary = summary + "\n";
			
			for(String key : tree.keySet())
			{
				//check if we have a true resolution
				resolution_search = tree.get(key);
				
				if(resolution_search == null)							
					summary = summary + key + "\n"; //otherwise, just include the key name
				else
					summary = summary + resolution_search.getSummaryOverview("\t ") + "\n";
					
					
			}
			
			
			return summary;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "get_string_details", e);
		}
		
		return summary;
	}
	
	public String get_domain_name_requests(String title, TreeMap<String, Resolution> tree)
	{
		try
		{
			summary = "";
			unique_domain_name_requests = 0;
			
			if(tree == null || tree.isEmpty())
				return "";
			
			summary = title.trim() + "\n";
			
			address_length = title.length();
			for(int i = 0; i < address_length; i++)
			{
				summary = summary + "=";
			}
				
			summary = summary + "\n";
			
			try	{	included_node.clear();} 	catch(Exception e){included_node = new TreeMap<String, Resolution>();}
			
			for(String key : tree.keySet())
			{
				//check if we have a true resolution
				resolution_search = tree.get(key);
				
				if(resolution_search == null)
					continue;
				
				if(included_node.containsKey(key))
					continue;
				
				if(included_node.containsValue(resolution_search))
					continue;

				++unique_domain_name_requests;
				
				included_node.put(resolution_search.address, resolution_search);								
				included_node.put(key, resolution_search);
				
				if(resolution_search == null)							
					summary = summary + key + "\n"; //otherwise, just include the key name
				else
					summary = summary + resolution_search.getSummaryOverview("\t ") + "\n";
					
					
			}
						
			
			try	{	included_node.clear();} 	catch(Exception e){included_node = new TreeMap<String, Resolution>();}
			
			return summary;
		}
		catch(ConcurrentModificationException cme)
		{
			driver.directive("Hold fast, I am currently modifying the domain name request tree...");
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "get_domain_name_requests", e);
		}
		
		
		return summary;
	}
	
	public String get_user_agent()
	{
		try
		{
			summary = "";
			
			if(this.tree_my_user_agent == null || tree_my_user_agent.isEmpty())
				return "";
			
			summary = "User Agent" + "\n";
			
			address_length = summary.length();
			for(int i = 0; i < address_length; i++)
			{
				summary = summary + "=";
			}
				
			summary = summary + "\n";
			
			for(User_Agent user_agent : tree_my_user_agent.values())
			{
				if(user_agent == null)
					continue;	
				
				summary = summary + user_agent.getSummary() + "\n"; 
					
					
			}
			
			
			return summary;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "get_string_details", e);
		}
		
		return summary;
	}
	
	public String get_specific_packet_statistics(String delimiter, boolean include_header)
	{
		try
		{
			packet_statistics = "";
			
			for(String key : this.tree_packet_count.keySet())
			{
				if(include_header)
					packet_statistics = packet_statistics + " " + key + ": " + this.tree_packet_count.get(key) + delimiter;
				else
					packet_statistics = packet_statistics + " " + this.tree_packet_count.get(key) + delimiter;
			}
			
			return packet_statistics;
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "get_specific_packet_statistics - " + this.src_ip, e);
		}
		
		return "";
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
			
			this.is_ipv4 = true;
			
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
	
	
	
	public String strip_MAC(String MAC)
	{
		try
		{
			if(MAC == null || MAC.equals(""))
				return MAC;
			
			MAC = MAC.replaceAll("\\-", "");
			MAC = MAC.replaceAll("\\:", "");
					
			return MAC;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "strip_MAC", e);
		}
						
		return MAC;
	}
	
	public boolean reset_packet_values()
	{
		try
		{
			this.packet_details = "";
			this.packet_dns_query = "";
			this.packet_dst_ip = "";
			this.packet_dst_mac = "";
			this.packet_dst_port = "";
			this.packet_dst_port_tcp = "";
			this.packet_dst_port_udp = "";
			this.packet_frame_time = "";
			this.packet_http_cookie = "";
			this.packet_http_referer = "";
			this.packet_http_request = "";
			this.packet_http_request_full_uri = "";
			this.packet_interface_name = "";
			this.packet_ip_protocol_designation_number = "";
			this.packet_protocol = "";
			this.packet_sensor_name = "";
			this.packet_src_ip = "";
			this.packet_src_mac = "";
			this.packet_src_port = "";
			this.packet_src_port_tcp = "";
			this.packet_src_port_udp = "";
			this.packet_transmission_type = "";
			this.packet_user_agent = "";
			this.packet_version = "";
			this.packet_virtual_host = "";
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "reset_packet_values", e);
		}
		
		return false;
	}
	
	
	
	
	public boolean update_protocol_packet(String protocol)
	{
		try
		{
			//
			//UPDATE INDEX OF ALL PROTOCOLS WE HAVE
			//
			try
			{
				if(!SOURCE.tree_protocol_header_names.containsKey(protocol))
					SOURCE.tree_protocol_header_names.put(protocol, protocol);
			}
			catch(Exception e)
			{
				//could be a concurrentmodification exception
			}
			
			try
			{
				//
				//UPDATE Node packet count based on protocol
				//
				if(!tree_packet_count.containsKey(protocol))
				{
					tree_packet_count.put(protocol,  1);
					tree_packet_count_OVERFLOW.put(protocol,  0);
				}
				
				//otw, it exists, check if we're nearing overflowing
				else if(tree_packet_count.get(protocol) >= (Integer.MAX_VALUE-9999))
				{
					tree_packet_count_OVERFLOW.put(protocol,  (tree_packet_count_OVERFLOW.get(protocol)+1));
					tree_packet_count.put(protocol,  0);
				}
				
				//otw, all is well, increment the count
				else 
				{
					tree_packet_count.put(protocol,  (tree_packet_count.get(protocol)+1));
				}
				
				updated_packet_count = true;
			}
			catch(Exception e)
			{
				//could be a concurrentmodification exception
			}
			
			//
			//UPDATE SNAPSHOT TOTALS - UNTIL RESET
			//

			try
			{
				//
				//UPDATE Node packet count based on protocol
				//
				if(!tree_snapshot_packet_count.containsKey(protocol))
				{
					tree_snapshot_packet_count.put(protocol,  new Tuple(protocol, 1));
					tree_snapshot_packet_count_OVERFLOW.put(protocol,  new Tuple(protocol, 1));
				}
				
				//otw, it exists, check if we're nearing overflowing
				else if(tree_snapshot_packet_count.get(protocol).value >= (Integer.MAX_VALUE-9999))
				{
					tree_snapshot_packet_count_OVERFLOW.get(protocol).increment();
					tree_snapshot_packet_count.get(protocol).value = 0;
				}
				
				//otw, all is well, increment the count
				else 
				{
					tree_snapshot_packet_count.get(protocol).increment();
				}
				
				updated_packet_count = true;
			}
			catch(Exception e)
			{
				//could be a concurrentmodification exception
			}
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "update_protocol_packet", e);
		}
		
		return false;
	}
	
	
	
	
	public String get_map_details(boolean include_map_header)
	{
		try
		{
			if(this.geo == null)
				return "";
			
			value_map = "";
			
			if(include_map_header)
			{
				value_map = "var location = {lat:\"" + this.geo.latitude + "\", lng:\"" + this.geo.longitude +"\"}; ";
				
				
				if(this.SANITIZE_MAC)
				{								
					value_map = value_map + "var device = {ID: 'Device Classification: [" + this.oui.replaceAll("'", "") + "]', data: '" + 
							"<br><b>MAC:</b> " + this.mac_sanitized;
				}
				else
				{
					value_map = value_map + "var device = {ID: 'Device Classification: [" + this.oui.replaceAll("'", "") + "]', data: '" + 
							"<br><b>MAC:</b> " + this.src_mac ;
				}
				
				value_map = value_map + "<br>";
			}
			
			
			
			value_map = value_map + "<b>Source Address</b>:&nbsp" + src_ip + "<br>";
			
			if(domain_name != null && !domain_name.trim().equals(""))
				value_map = value_map + "<b>Domain Name</b>:&nbsp&nbsp&nbsp&nbsp" + domain_name + "<br>";
			
			value_map = value_map + "<br>";
			
			value_map = value_map + "<b>Themis Sensor Name</b>: " + packet_sensor_name + "<br>";
			value_map = value_map + "<b>Interface Captured On</b>: " + packet_interface_name + "<br>";
			value_map = value_map + "<b>Packet Protocol</b>: " + packet_protocol + "<br>";
			value_map = value_map + "<b>First Packet Received</b>: " + first_frame_time + "<br>";
			value_map = value_map + "<b>Last  Packet Received</b>: " + last_frame_time + "<br>";
			
			if(!ALERT_DATABASE.isEmpty())
				value_map = value_map + "<b>ALERT DETECTED ON THIS DEVICE!</b><br>";
			
			value_map = value_map + "<br>";
			
			//GEO
			if(geo != null)
				value_map = value_map + geo.get_map_details();	
			
			if(include_map_header)
			{
				//terminate
				if(include_map_header)			
					value_map = value_map + "'};	plotMarker(map, location, device);";
			}
					 			 			 															
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "get_map_details", e);
		}
		
		return value_map;
	}
	
	public Node_Map_Details get_map_node(boolean include_map_header)
	{
		try
		{
			if(this.geo == null)
				return null;
			
			if(node_map_details == null)
				node_map_details = new Node_Map_Details(geo.latitude, geo.longitude, this.get_map_details(true));
			else
				node_map_details.details = this.get_map_details(include_map_header);
			
			return node_map_details;
		}
		
		catch(Exception e)
		{
			driver.eop(myClassName, "get_map_node", e);
		}
		
		return null;
	}
	
	
	
	
	public static LinkedList<Node_Map_Details> get_linked_list_of_map_details_from_each_node(boolean include_map_header)
	{
		try
		{
			if(SOURCE.TREE_SOURCE_NODES == null || SOURCE.TREE_SOURCE_NODES.isEmpty())
				return null;
			
			try	{	list_map_details.clear();} catch(Exception e){list_map_details = new LinkedList<Node_Map_Details>();}
			
			for(SOURCE node : SOURCE.TREE_SOURCE_NODES.values())
			{
				if(node.geo == null)
					continue;
				
				list_map_details.add(node.get_map_node(include_map_header));
			}
									
			return list_map_details;
		}
		catch(Exception e)
		{
			System.out.println("Check through get_linked_list_of_map_details_from_each_node mtd in class: " + myClassName);
		}
		
		return null;
	}
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
}
