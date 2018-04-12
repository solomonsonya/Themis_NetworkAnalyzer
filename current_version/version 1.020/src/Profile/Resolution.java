/**
 * This is a whois node along with additional information for each request received
 * 
 * note: all addresses stored in the tree are lowercase-trimmed
 * 
 * @author Solomon Sonya
 */

package Profile;

import Driver.*;
import GEO_Location.GEO_Location;
import ResolutionRequest.ResolutionRequest_ThdSocket;
import Worker.ThdWorker;
import java.net.InetAddress;
import java.util.*;
import Parser.*;
import GEO_Location.*;

public class Resolution 
{
	public static final String myClassName = "Resolution";
	public volatile Driver driver = new Driver();
	
	public static volatile boolean drop_subdomains = false;
			
	/**all new requests initially start here until a resolution is found for them*/
	public static volatile TreeMap<String, Resolution> tree_unresolved_request = new TreeMap<String, Resolution>();
		
	public volatile boolean is_private_non_routable_address = false;
	
	public static volatile boolean resolve_inet_address = true;
	
	public volatile TreeMap<String, SOURCE> tree_source = new TreeMap<String, SOURCE>();
	
	public volatile boolean is_private_non_routable_ip = false;
	
	public volatile boolean ALERT = false;
	public volatile String address = "";
	public volatile String address_lowercase_trimmed = "";
	public volatile String address_normalized = "";
	public volatile String alert_indicator = " ";
	public volatile String resolution_summary = "";
	public volatile String [] jtable_row = new String[8];
	public volatile String domain_name = "";
	public volatile String name_server = "";
	public volatile String first_contact_time = "";
	/**Last time a node was linked to this resource*/
	public volatile String last_link_time = "";
	public volatile boolean resolution_complete = false;
	public volatile String internal_ipv4 = "";
	
	public volatile GEO_Location geo = null;
	
	public volatile boolean is_ipv4 = false; 
	public volatile String found_value = "";
	public volatile String value_domain_name = null;
	
	public volatile SOURCE parent = null;
	
	public volatile String data_view_summary = "";
	public volatile int address_length = 0;
	
	public volatile LinkedList<String> list_dns_query_names = new LinkedList<String>();
	public volatile LinkedList<String> list_dns_response_addresses = new LinkedList<String>();
	
	/**All resources, regardless if resolved or unresolved, go into this in order to help us keep track of all resolutions in the syste*/
	public static volatile TreeMap<String, Resolution> TREE_RESOURCE = new TreeMap<String, Resolution>();
	
	/**to indicate if the worker thread need to update the gui if an update has occurred*/
	public static volatile boolean updated_data_refresh_required = false;
	
	public Resolution(String addr, SOURCE source)
	{
		try
		{
			address = addr;
			address_lowercase_trimmed = addr;
			address_normalized = this.normalize_lookup(addr);
			this.link_requestor(source);
			parent = source;
			first_contact_time = driver.time.getTime_Current_hyphenated_with_seconds("-");
			last_link_time = driver.time.getTime_Current_hyphenated_with_seconds("-");
			
			initialize(source);
			
			ThdWorker.refresh_jtable_resolution = true;
						
			if(addr != null)
			{
				address_length = address.length();
				address_lowercase_trimmed = addr.toLowerCase().trim();
			}
			
			//
			//Check GEO Location - address_normalized
			//
			if(!this.is_private_non_routable_address && !GEO_Location.TREE_GEO_LOCATION.containsKey(address_normalized) && !GEO_Location.TREE_NOT_FOUND.containsKey(address_normalized))
			{
				//neither tree has the dst ip address, request for resolution
				GEO_Location geo = new GEO_Location(address_normalized);
			}
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "Constructor - 1", e);
		}
	}
	
	
	
	public boolean initialize(SOURCE source)
	{
		try
		{			
			if(address == null || address.trim().equals(""))
				return false;
			
			address = address.trim();
			
			if(TREE_RESOURCE.containsKey(address_lowercase_trimmed))
				TREE_RESOURCE.get(this.address_lowercase_trimmed).link_requestor(source);			
			else
			{
				TREE_RESOURCE.put(this.address_lowercase_trimmed, this);
				
				request_to_resolve(source, this.address_lowercase_trimmed);
			}
			
			if(address_normalized != null && !address_normalized.trim().equals("") && this.TREE_RESOURCE.containsKey(this.address_normalized))
				TREE_RESOURCE.get(this.address_normalized).link_requestor(source);
			else
			{
				TREE_RESOURCE.put(this.address_normalized, this);
				request_to_resolve(source, this.address_normalized);
			}
			
			if(!this.resolution_complete && !tree_unresolved_request.containsValue(this))
				tree_unresolved_request.put(this.address_lowercase_trimmed, this);
			
			/*if(tree_unresolved_request.containsKey(address.toLowerCase().trim()))
			{
				Resolution resolution = tree_unresolved_request.get(address.toLowerCase().trim());
				resolution.link_requestor(source);
				return false;
			}
			
			else if(tree_resolution.containsKey(address.toLowerCase().trim()))
			{
				Resolution resolution = this.tree_resolution.get(address.toLowerCase().trim());
				resolution.link_requestor(source);
			}
			else//unresolved tree doesn't contain me
			{
				tree_unresolved_request.put(address.toLowerCase().trim(),  this);				
			}	*/		
				
			this.is_private_non_routable_address = this.is_private_non_routable_ip(address);
			
			if(is_private_non_routable_address)
				internal_ipv4 = "" + is_private_non_routable_address;
			
			
			//internal_ipv4 = "" + is_private_non_routable_address;
			
			/*if(is_internal_address)
				this.internal_ipv4 = "" + is_internal_address;
			else
				this.internal_ipv4 = this.address;*/
			
			
			last_link_time = driver.time.getTime_Current_hyphenated_with_seconds("-");
			
			return true;
		}
		catch(ConcurrentModificationException con)
		{
			driver.directive("Holdfast! I am currently executing from the list at the same time");						
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "Constructor - 1", e);
		}
		
		return false;
	}
	
	public boolean request_to_resolve(SOURCE source, String request)
	{
		try
		{
			if(request == null || request.trim().equals(""))
				return false;
			
			request = request.toLowerCase().trim();
			
						
			if(source != null)
				sop("Sending resolution for [" + request + "] from [" + source.src_ip + "]");
			else
				sop("Sending resolution for [" + request + "]");
			
			//new node, request excalibur resolve this address
			for(ResolutionRequest_ThdSocket skt : ResolutionRequest_ThdSocket.ALL_CONNECTIONS)
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
			
			//
			//Check GEO Location - address_normalized
			//
			if(!this.is_private_non_routable_ip(request) && !GEO_Location.TREE_GEO_LOCATION.containsKey(request) && !GEO_Location.TREE_NOT_FOUND.containsKey(request))
			{
				//neither tree has the dst ip address, request for resolution
				GEO_Location geo = new GEO_Location(request);
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
	
	public boolean is_private_non_routable_ip(String ip)
	{
		try
		{
			if(ip == null)
				return true;
			
			ip = ip.trim();
			
			if(ip.equals(""))
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
				this.domain_name = ip;
				return false;
			}
			
			is_ipv4 = true;
			
			this.internal_ipv4 = ip;
			
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
	
	public boolean link_requestor(SOURCE source)
	{
		try
		{
			if(source == null || source.src_ip == null || source.src_ip.trim().equals("") || source.src_ip.trim().equalsIgnoreCase(this.address.trim()))
				return false;
			
			//don't add this source if we have it in the address of ip addresses about ourself from the dns response address
			if(this.list_dns_response_addresses != null && this.list_dns_response_addresses.contains(source.src_ip.trim()))
				return true;
			
			if(this.tree_source.containsKey(source.src_ip.toLowerCase().trim()))
				return true;
			
			if(this.tree_source.containsValue(source))
				return true;
			
			this.tree_source.put(source.src_ip.toLowerCase().trim(), source);
			
			this.sop("New Source [" + source.src_ip + "] has been linked to Resolution [" + this.address + "]");
			
			//ensure source has us in it's list
			
			last_link_time = driver.time.getTime_Current_hyphenated_with_seconds("-");
			
			updated_data_refresh_required = true;
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "link_requestor", e);
		}
		
		return false;
	}
	
	public String [] get_jtable_row_summary(String delimiter, boolean include_data)
	{
		try
		{
			jtable_row[0] = this.address;
			jtable_row[1] = this.alert_indicator;
			jtable_row[2] = ""+this.tree_source.size();
			jtable_row[3] = this.domain_name;
			jtable_row[4] = this.name_server;
			jtable_row[5] = this.first_contact_time;
			jtable_row[6] = ""+this.resolution_complete;
			jtable_row[7] = "" + internal_ipv4;			
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "get_jtable_row_summary", e);
		}
		
		return jtable_row;
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
				driver.sop(myClassName + " --> " + line);
			}
			
			return true;
		}
		
		catch(Exception e)
		{
			driver.eop(myClassName, "sop", e);
		}
		
		return false;
	}
	
	
	public String get_domain_name_list(String title, String delimiter, LinkedList<String> list)
	{
		try
		{
			if(list == null || list.isEmpty())
				return "";
			
			value_domain_name = title + delimiter;
			
			for(String domain : list)
			{
				if(domain == null)
					continue;
				
				/*if(domain.equalsIgnoreCase(this.domain_name))
					continue;*/
				
				value_domain_name = value_domain_name + domain + delimiter;
			}
			
			return value_domain_name;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "get_domain_name_list", e);
		}
		
		return this.domain_name;
	}
	
	public String getSummaryOverview(String delimiter)
	{
		try
		{
			//if(this.domain_name != null && !this.domain_name.trim().equals(""))
			//	return this.address + delimiter + " Domain Name(s):" + delimiter + this.get_domain_name_list(" \t ", this.list_dns_query_names) + delimiter + " IP Address(es): " + delimiter + this.get_domain_name_list(" \t ", this.list_dns_response_addresses);						
			
			
			
			return this.address + "\t\t" + this.get_domain_name_list("Domain Name:", " \t ", this.list_dns_query_names) + "\t" + this.get_domain_name_list("IP Address:", " \t ", this.list_dns_response_addresses);
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "getSummaryOverview", e);
		}
		
		return this.address + "-/-";
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
						
			if(key.equalsIgnoreCase("address") || key.equalsIgnoreCase("source") || key.equalsIgnoreCase("src") || key.equalsIgnoreCase("ip") || key.equalsIgnoreCase("key"))
				found_value =  address;
			
			else if(key.equalsIgnoreCase("alert_indicator") || key.equalsIgnoreCase("alert indicator") || key.equalsIgnoreCase("alert") )
				found_value = alert_indicator ;
			
			else if(key.equalsIgnoreCase("domain_name") || key.equalsIgnoreCase("domain name"))
				found_value = domain_name ;
			
			else if(key.equalsIgnoreCase("cardinality") || key.equalsIgnoreCase("size") || key.equalsIgnoreCase("count"))
				found_value = ""+this.tree_source.size() ;
			
			else if(key.equalsIgnoreCase("name_server") || key.equalsIgnoreCase("name server") || key.equalsIgnoreCase("nameserver"))
				found_value = name_server ;
			
			else if(key.equalsIgnoreCase("first_contact_time") || key.equalsIgnoreCase("first contact time"))
				found_value =  first_contact_time;
			
			else if(key.equalsIgnoreCase("last_link_time") || key.equalsIgnoreCase("last link time"))
				found_value =  last_link_time;
			
			else if(key.equalsIgnoreCase("resolution_complete") || key.equalsIgnoreCase("resolution complete"))
				found_value =  ""+resolution_complete;
			
			else if(key.equalsIgnoreCase("internal_ipv4") || key.equalsIgnoreCase("internal ipv4"))
				found_value =  internal_ipv4;
						
			
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
			
			 if(specification.startsWith("*") && specification.endsWith("*"))
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
	
	
	
	public String getDataViewInformation(String delimiter)
	{
		try
		{
			data_view_summary = "Source Address: " + this.address + "\n";
			
			
			for(int i = 0; i < address_length+16; i++)
			{
				data_view_summary = data_view_summary + "=";
			}
			
			data_view_summary = data_view_summary + delimiter + delimiter;
			
			if(this.domain_name != null && !this.domain_name.trim().equals(""))
			{
				data_view_summary = data_view_summary + "Domain Name:\n=============" + "\n";
				data_view_summary = data_view_summary + this.domain_name + "\n\n";
			}
			
			if(this.list_dns_response_addresses != null && this.list_dns_response_addresses.size() > 0)
			{
				data_view_summary = data_view_summary + "IP Address:\n=============";
				data_view_summary = data_view_summary + this.get_domain_name_list("", "\n", this.list_dns_response_addresses);
				
				data_view_summary = data_view_summary + "\n";
			}
			
			if(this.name_server != null && !this.name_server.trim().equals(""))
			{
				data_view_summary = data_view_summary + "Name Server:\n============";
				data_view_summary = data_view_summary + this.name_server + "\n\n";
			}
			
			data_view_summary = data_view_summary + "Details:\n========" + "\n";
			data_view_summary = data_view_summary + "First Contact Time : " + this.first_contact_time+ "\n";
			data_view_summary = data_view_summary + "Last Node Link Time: " + this.last_link_time+ "\n";
			data_view_summary = data_view_summary + "Cardinality: " + this.tree_source.size()+ "\n";
			
			if(alert_indicator != null && !alert_indicator.trim().equals(""))
			{
				data_view_summary = data_view_summary + "Alert Indication: " + this.alert_indicator + "\n";
			}
			
			data_view_summary = data_view_summary + "\n";
			
			if(geo != null)
			{
				data_view_summary = data_view_summary + "GEO Location:\n=============\n";
				data_view_summary = data_view_summary + geo.toString("\n") + "\n";
			}
			
			if(this.tree_source != null && this.tree_source.size() > 0)
			{
				data_view_summary = data_view_summary + "\n" + "Requesting (Source) Nodes:\n==========================";
				
				for(SOURCE node : this.tree_source.values())
				{
					if(node == null)
						continue;										
					
					data_view_summary = data_view_summary + "\n" + node.src_ip + "\t" + node.src_mac;
				}
			}
					 			 			 															
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "getDataViewInformation", e);
		}
		
		return data_view_summary;
	}
	
	
	public boolean add_dns_query_name(String dns_qry)
	{
		try
		{
			if(dns_qry == null || dns_qry.trim().equals(""))
				return false;
			
			dns_qry = dns_qry.toLowerCase().trim();
			
			if(this.domain_name == null || this.domain_name.trim().equals(""))
				this.domain_name = dns_qry;
			
			//link this new address to self as well...
			if(!TREE_RESOURCE.containsKey(dns_qry))
			{
				TREE_RESOURCE.put(dns_qry,  this);
				this.request_to_resolve(null, dns_qry);
			}
			
			if(!list_dns_query_names.contains(dns_qry))
			{
				list_dns_query_names.add(dns_qry);
				
				if(this.internal_ipv4 != null && !this.internal_ipv4.trim().equals("") && !(internal_ipv4.toLowerCase().equals("false") || internal_ipv4.toLowerCase().equals("true")))
				{
					log_dns(dns_qry, internal_ipv4);
				}
			}
			
			updated_data_refresh_required = true;
			
			
			
			return true;
		}
		catch(ConcurrentModificationException cme)
		{
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "add_dns_query_name");
		}
		
		return false;
	}
	
	public boolean log_dns(String domain_name, String dst_ip)
	{
		try
		{
			//
			//log dns resolution
			//
			if(Parser.log_dns == null)
			{
				Parser.log_dns = new Log("parser/dns/",  "dns_query_response", 250, 999999999);
				Parser.log_dns.OVERRIDE_LOGGING_ENABLED = true;
			}
			
			Parser.log_dns.log_directly(domain_name + "\t" + dst_ip);
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "log_dns", e);
		}
		
		return false;
	}
	
	
	public boolean add_dns_response_address(String address)
	{
		try
		{
			if(address == null || address.trim().equals(""))
				return false;
			
			address = address.toLowerCase().trim();
			
			if(this.internal_ipv4 == null || this.internal_ipv4.trim().equals("") || this.internal_ipv4.toLowerCase().trim().equals("false"))
				this.internal_ipv4 = address;							
			
			if(!list_dns_response_addresses.contains(address))
			{
				list_dns_response_addresses.add(address);
				
				this.request_to_resolve(null, address);
				
				if(this.domain_name != null && !this.domain_name.trim().equals(""))
				{
					log_dns(domain_name, address);
				}
			}
			
			//link this new address to self as well...
			if(!TREE_RESOURCE.containsKey(address))
			{
				TREE_RESOURCE.put(address,  this);				
				
			}
			
			//remove the address to ensure it's not included in linked sources
			if(this.tree_source.containsKey(address))
				tree_source.remove(address);
			
			updated_data_refresh_required = true;
			
			
			
			return true;
		}
		catch(ConcurrentModificationException cme)
		{
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "add_dns_response_address");
		}
		
		return false;
	}
	
	
	public String normalize_lookup(String lookup)
	{
		try
		{
			String []array_ip = null;
			
			if(lookup == null || lookup.trim().equals(""))
				return "";
			
			lookup = lookup.trim();
			
			if(lookup.toLowerCase().startsWith("https://"))
				lookup = lookup.substring(8).trim();
			if(lookup.toLowerCase().startsWith("http://"))
				lookup = lookup.substring(7).trim();
			if(lookup.toLowerCase().startsWith("www1."))
				lookup = lookup.substring(5).trim();
			if(lookup.toLowerCase().startsWith("www3."))
				lookup = lookup.substring(5).trim();
			if(lookup.toLowerCase().startsWith("ww3."))
				lookup = lookup.substring(4).trim();
			if(lookup.toLowerCase().startsWith("www."))
				lookup = lookup.substring(4).trim();
			if(lookup.toLowerCase().startsWith("/"))
				lookup = lookup.substring(1).trim();
			if(lookup.toLowerCase().startsWith("/"))
				lookup = lookup.substring(1).trim();
			if(lookup.toLowerCase().startsWith("."))
				lookup = lookup.substring(1).trim();
			
			//bifurcate domain name from URL
			if(lookup.contains("/"))
			{
				array_ip = lookup.split("\\/");				
				
				if(array_ip[0] != null && !array_ip[0].trim().equals(""))
					lookup = array_ip[0].trim();
				else if(array_ip.length > 1 && array_ip[2] != null && !array_ip[2].trim().equals(""))
					lookup = array_ip[0].trim();				
			}
			
			lookup = lookup.replaceAll("\\*", "");
			
			
			//drop subdomains
			if(Resolution.drop_subdomains)
			{
											
				array_ip = lookup.split("\\.");
				
				//separate look, also process full subdomain request just in case it reveals interesting information
				if(array_ip != null && array_ip.length > 2)
				{
					//Whois whois = new Whois(lookup, true);
				}
				
				//check if we have many subdomains
				if(array_ip != null && array_ip.length > 4)
				{
					lookup = array_ip[array_ip.length-2] + "." + array_ip[array_ip.length-1] ;
				}
				
				//check if we may have an ip address
				//NOTE: BELOW SHOULD START A NEW IF control flow, do not make it an else if!
				else if(array_ip != null && array_ip.length > 3)
				{
					try
					{
						Integer.parseInt(array_ip[0].trim());
						Integer.parseInt(array_ip[1].trim());
						Integer.parseInt(array_ip[2].trim());
						Integer.parseInt(array_ip[3].trim());
						
						//first 4 octets are ip addresses					
						lookup = array_ip[0].trim() + "." + array_ip[1].trim() + "." +array_ip[2].trim() + "." + array_ip[3].trim();
					}
					catch(Exception e)
					{
						//something went wrong, so consider it a subdomain...
						if(array_ip != null && array_ip.length > 1)
							lookup = array_ip[array_ip.length-2] + "." + array_ip[array_ip.length-1];
					}
				}
				
				//not ip address, thus remove subdomains
				else if(array_ip != null && array_ip.length > 1)
					lookup = array_ip[array_ip.length-2] + "." + array_ip[array_ip.length-1];
			}
			
			lookup = lookup.toLowerCase().trim();			
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "normalize_lookup", e, true);
		}
		
		return lookup;
	}
	
	
	
	
	
	
}
