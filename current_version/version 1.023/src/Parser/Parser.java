package Parser;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Calendar;
import java.util.Date;
import java.util.LinkedList;
import java.util.TreeMap;
import Driver.*;
import Driver.Log;
import Driver.StandardInListener;
import Driver.Start;
import Encryption.Encryption;
import Profile.Resolution;
import Profile.SOURCE;
import ResolutionRequest.ResolutionRequest_ThdSocket;
//import Sound.ThreadSound;
import Worker.ThdWorker;
import GEO_Location.*;

public class Parser extends Thread implements Runnable
{
	public static final String myClassName = "Parser";
	
	public static volatile boolean PARSER_ENABLED = true;
	
	public static final String delimiter = "\t";
	public static Driver driver = new Driver();
	
	public volatile String myInterface = "";
	
	public volatile Resolution resolution_to_use_in_your_search = null;
	
	public static Log log = null;
	public static Log log_dns = null;
	public static Log ALERT = null; 
	public static volatile boolean first_start = true;
	
	public volatile String [] array = null, array_octet = null;
	
	public volatile String SIGNATURES = "";
	public volatile String [] ARR_SIGNATURES = null;
	
	public volatile String curr_time = "";
	
	public volatile int array_length = 0;
	public volatile SOURCE ndeSource = null;
	public volatile String version = "";
	public volatile String sensor_name = "";
	public volatile String interface_name = "";
	public volatile String frame_time = ""; 
	public volatile String ip_protocol = ""; 
	public volatile String src_mac = ""; 
	public volatile String src_ip = ""; 
	public volatile String src_port_tcp = ""; 
	public volatile String src_port_udp = ""; 
	public volatile String protocol = ""; 
	public volatile String dst_mac = ""; 
	public volatile String dst_ip = "";
	public volatile String dst_port_tcp = ""; 
	public volatile String dst_port_udp = ""; 
	public volatile String dns_query = ""; 
	public volatile String http_referer = ""; 
	public volatile String http_request_full_uri = ""; 
	public volatile String http_request = ""; 
	public volatile String http_cookie = ""; 
	public volatile String details = "";
	
	public volatile String packet_dst_port = "";
	public volatile String packet_src_port = "";
	public volatile String packet_transmission_type = "";
	public volatile boolean added_new_node = false;
	public volatile String value = "";	
	public volatile String dns_query_response_value = "";
	public volatile boolean dst_ip_is_private_non_routable_address = false;
	public volatile String full_uri_trimmed = "";
	public volatile String host_virtual = "";
	public volatile String user_agent = "";
	
	
	public volatile String name_server = "";
	public volatile String inet_address = "";
	public volatile String [] array_ip = null;
	public volatile int octet_1 = 0;
	public volatile int octet_2 = 0;
	public volatile int octet_3 = 0;
	public volatile int octet_4 = 0;
	
	public volatile int octet_1_dns = 0;
	public volatile int octet_2_dns = 0;
	public volatile int octet_3_dns = 0;
	public volatile int octet_4_dns = 0;
	
	public volatile InetAddress inet = null;
	
	public volatile static LinkedList<Parser> list_parsers = new LinkedList<Parser>();
	
	public final TreeMap<String, String> TREE_PROTOCOL_LOOKUP_TABLE = new TreeMap<String, String>();
	
	public volatile String last_parser_update = "Awaiting input...";
	public volatile DateTimeFormatter dateFormat = DateTimeFormatter.ofPattern("yyyy" + "-" + "MM" + "-" + "dd" + "-" + "HH" + "mm" + ":" + "ss");
	public volatile LocalDateTime date_now = LocalDateTime.now();
	
	Date dateTime = new Date();
	
	public Parser()
	{
		try
		{		
			
			if(first_start)
			{
				first_start = false;
				log = new Log("parser/sensor_data/",  "parser", 250, 999999999);
				
				//write header
				log.log_directly("version" + delimiter + "sensor_name" + delimiter + "interface_name" + delimiter + "frame_time" + delimiter + "ip_protocol" + delimiter + "src_mac" + delimiter + "src_ip" + delimiter + "src_port_tcp" + delimiter + "src_port_udp" + delimiter + "protocol" + delimiter + "dst_mac" + delimiter + "dst_ip" + delimiter + "dst_port_tcp" + delimiter + "dst_port_udp" + delimiter + "dns_query" + delimiter + "http_referer" + delimiter + "http_request_full_uri" + delimiter + "http_request" + delimiter + "http_cookie" + delimiter + "details");
								
			}
			
			//populate protocol lookup table
			populate_protocol_lookup_table();
			
			this.start();
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "Constructor - 1", e);
		}
	}
	
	public void run()
	{
		try
		{
			sop("Started and ready to process packets from Sensor!");
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "run", e);
		}
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
				driver.sop(myClassName + " [" + this.getId() + "] --> " + line);
			}
			
			return true;
		}
		
		catch(Exception e)
		{
			driver.eop(myClassName, "sop", e);
		}
		
		return false;
	}
	
	/**
	 * NOTE: to prevent gratuitous ARPS, let's only process from nodes we've already seen... then if this request becomes excessive, we can alert!
	 * also note, this is just for the ARP request. I disregard ARP replies since it should be a source node communicating here, and we should 
	 * already have that source node linked
	 * @return
	 */
	public boolean process_ARP(String line)
	{
		try
		{
			//see if we can get the source node from the source MAC
			if(this.src_mac == null || src_mac.trim().equals(""))
				return false;
			
			
			if(!SOURCE.tree_source_nodes_MAC.containsKey(src_mac))
				return false;
			
			this.ndeSource = SOURCE.tree_source_nodes_MAC.get(src_mac);
			
			if(ndeSource == null)
				return false;
			
			ndeSource.packet_transmission_type = protocol;
			
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
				if(!ndeSource.tree_packet_count.containsKey(protocol))
				{
					ndeSource.tree_packet_count.put(protocol,  1);
					ndeSource.tree_packet_count_OVERFLOW.put(protocol,  0);
				}

				//otw, it exists, check if we're nearing overflowing
				else if(ndeSource.tree_packet_count.get(protocol) >= (Long.MAX_VALUE-9999))
				{
					ndeSource.tree_packet_count_OVERFLOW.put(protocol,  (ndeSource.tree_packet_count_OVERFLOW.get(protocol)+1));
					ndeSource.tree_packet_count.put(protocol,  0);
				}

				//otw, all is well, increment the count
				else 
				{
					ndeSource.tree_packet_count.put(protocol,  (ndeSource.tree_packet_count.get(protocol)+1));
				}
			}
			catch(Exception e){}//could be concurrent modification
			
			//
			//UPDATE VALUES
			//
			ndeSource.last_http_request = "";
			ndeSource.packet_dns_query = "";
			
			ndeSource.set_version(version);
			ndeSource.set_sensor_name(sensor_name);
			ndeSource.set_interface_name(interface_name);
			ndeSource.set_frame_time(frame_time); 
			ndeSource.set_ip_protocol(ip_protocol); 
			ndeSource.set_details(details);
			ndeSource.set_protocol(protocol); 
			ndeSource.set_dst_mac(dst_mac); 
			

			//
			//set destination ip from who has...
			//
			if(details != null && details.toLowerCase().contains("who has"))
			{
				array = details.trim().toLowerCase().split("who has");
				
				if(array != null && array.length > 0)
				{
					value = array[0];
					
					if((value == null || value.trim().equals("")) && array.length > 1)
						value = array[1];
					
					if(value != null && !value.trim().equals(""))
					{
						array = value.split(" ");
						
						value = array[0];
						
						if((value == null || value.trim().equals("")) && array.length > 1)
							value = array[1];
						
						if(value != null && value.trim().endsWith("?"))
						{
							value = value.substring(0, value.length()-1);
							ndeSource.set_dst_ip(value, null, null, null, null);
						}												
					}										
				}
			}
			
			//
			//clear
			//
			ndeSource.packet_src_port = "";
			ndeSource.packet_src_port_tcp = "";
			ndeSource.packet_src_port_udp = "";
			ndeSource.packet_dst_port = "";
			ndeSource.packet_dst_port_tcp = "";
			ndeSource.packet_dst_port_udp = "";			
			ndeSource.trimmed_domain_name_request = "";
			ndeSource.packet_dns_query = ""; 			
			ndeSource.trimmed_http_referer = "";
			ndeSource.packet_http_referer = ""; 			
			ndeSource.trimmed_http_full_uri_request = "";
			ndeSource.packet_http_request_full_uri = ""; 			
			ndeSource.trimmed_http_request = "";
			ndeSource.packet_http_request = ""; 			
			ndeSource.packet_http_cookie = ""; 
			ndeSource.packet_virtual_host = "";
			ndeSource.packet_user_agent = "";
			
			
			//
			//LOG
			//
			if(log != null)
				log.log_directly(line);
			
			
			
			return true;
		}
			
			
		catch(Exception e)
		{
			//driver.eop(myClassName, "process_ARP", e);
		}
		
		return false;
	}
	
	
	
	public boolean parse(String line)
	{
		try
		{		
			if(line == null || line.trim().equals(""))
				return false;
			
			if(line.startsWith("Successfully connected to"))
			{
				driver.directive("\n" + line + "\n");
				return true;
			}
			
			/*if(!PARSER_ENABLED)
				return false;*/
						
			
			//1.0	Themis NetSensor_1515744488334	eth0	Jan 12, 2018 02:09:22.354575973 CST	17	00:0c:29:e3:c4:ce	192.168.0.104		43071	DNS	c8:d3:a3:59:7b:f4	192.168.0.1		53	www.excite.com					Standard query 0x600b A www.excite.com
			//1.0	Themis NetSensor_1515744488334	eth0	Jan 12, 2018 02:09:22.403969754 CST	6	00:0c:29:e3:c4:ce	192.168.0.104	35816		HTTP	c8:d3:a3:59:7b:f4	74.113.233.95	80				http://www.excite.com/	1	__utma=47975283.1741087699.1515293665.1515363591.1515744445.3; __utmz=47975283.1515293665.1.1.utmccn=(direct)|utmcsr=(direct)|utmcmd=(none); __gads=ID=fcf2e689e94c71a7:T=1515293667:S=ALNI_MY98aUJMGM78oLr3O6Cdc6Tw-lOug; PC=I%3D0%26; anx="u=EA58EECD-8B40-4E83-8C9A-D691BCB32C05&fv=1515293808024&lv=1515744536623&nv=3&t=-&v=-&p=-&si=-&sn=-&od=none&op=-&ok=-&om=-&ob=-&oc=-&os=-&w=1920&h=1080&cd=24&f=-&g=-"; TS017b523b=01498635475a4178b6ffce2af42451a026f273149dce33a5942f49b61debab205059c51871; __utmb=47975283; __utmc=47975283; OX_plg=pm; anxs="s=911939532&sv=1515744536610&sd=none&sp=-&sk=-&sm=-&sb=-&sc=-&ss=-"	GET / HTTP/1.1

			//command for version 1: -T fields -e frame.time -e ip.proto -e eth.src -e ip.src -e tcp.srcport -e udp.srcport -e _ws.col.Protocol -e eth.dst -e ip.dst -e tcp.dstport -e udp.dstport -e dns.qry.name -e http.referer -e http.request.full_uri -e http.request -e http.cookie -e _ws.col.Info";
			
			array = line.split(this.delimiter);		
			
			array_length = array.length;
			
			if(array == null || array_length < 12)
			{
				driver.log_unrecognized(line);
				return false;
			}
			
			//sop("Ready to process line of size[" + array.length + "] --> " + line);
			
			last_parser_update = getTime_Current_hyphenated_with_seconds();
			
			if(StandardInListener.intrface != null)
				StandardInListener.intrface.jpnlHeap.last_sensor_update = last_parser_update;
			
			//
			//init
			//
			version = "";
			sensor_name = "";
			interface_name = "";
			frame_time = ""; 
			ip_protocol = ""; 
			src_mac = ""; 
			src_ip = ""; 
			src_port_tcp = ""; 
			src_port_udp = ""; 
			protocol = ""; 
			dst_mac = ""; 
			dst_ip = ""; 
			dst_port_tcp = ""; 
			dst_port_udp = ""; 
			dns_query = ""; 
			http_referer = ""; 
			http_request_full_uri = ""; 
			http_request = ""; 
			http_cookie = ""; 
			details = "";
			packet_dst_port = "";
			packet_src_port = "";
			packet_transmission_type = "";
			added_new_node = false;
			inet = null;
			dst_ip_is_private_non_routable_address = false;
			resolution_to_use_in_your_search = null;
			full_uri_trimmed = "";
			host_virtual = "";
			user_agent = "";
			
			//
			//assign
			//
			version 		= array[0].replaceAll("\t", "").trim();
			sensor_name 	= array[1].replaceAll("\t", "").trim();
			interface_name 	= array[2].replaceAll("\t", "").trim();
			frame_time 		= array[3].replaceAll("\t", "").trim(); 
			ip_protocol 	= array[4].replaceAll("\t", "").trim(); 
			src_mac 		= array[5].replaceAll("\t", "").trim(); 
			src_ip 			= array[6].replaceAll("\t", "").trim(); 
			src_port_tcp 	= array[7].replaceAll("\t", "").trim(); 
			src_port_udp 	= array[8].replaceAll("\t", "").trim(); 
			protocol 		= array[9].replaceAll("\t", "").toUpperCase().trim(); 
			dst_mac 		= array[10].replaceAll("\t", "").trim(); 
			dst_ip 			= array[11].replaceAll("\t", "").trim(); 
			

			if(array_length > 12)
				dst_port_tcp 	= array[12].replaceAll("\t", "").trim(); 

			if(array_length > 13)
				dst_port_udp 	= array[13].replaceAll("\t", "").trim(); 
			
			if(array_length > 14)
			{
				dns_query 		= array[14].replaceAll("\t", "").trim();
				
				//normalize
				dns_query = this.normalize_lookup(dns_query, false);
			}

			if(array_length > 15)
				http_referer 	= array[15].replaceAll("\t", "").trim(); 

			if(array_length > 16)
				http_request_full_uri = array[16].replaceAll("\t", "").trim(); 

			if(array_length > 17)
				http_request 	= array[17].replaceAll("\t", "").trim(); 

			if(array_length > 18)
				http_cookie 	= array[18].replaceAll("\t", "").trim(); 

			if(array_length > 19)
				details 		= array[19].replaceAll("\t", "").trim();
			
			if(array_length > 20)
				host_virtual	= array[20].replaceAll("\t", " ").trim();
			
			if(array_length > 21)				
				user_agent		= array[21].replaceAll("\t", " ").trim();
			
			
			if(dst_port_tcp != null && !dst_port_tcp.equals(""))
			{
				packet_dst_port = dst_port_tcp;
				packet_transmission_type = "TCP";
			}
			else if(dst_port_udp != null && !dst_port_udp.equals(""))
			{
				packet_dst_port = dst_port_udp;
				packet_transmission_type = "UDP";
			}
			
			
			if(src_port_tcp != null && !src_port_tcp.equals(""))
			{
				packet_src_port = src_port_tcp;
				packet_transmission_type = "TCP";
			}
			else if(src_port_udp != null && !src_port_udp.equals(""))
			{
				packet_src_port = src_port_udp;
				packet_transmission_type = "UDP";
			}
			
			//
			//HANDLE SPECIFIC PROTOCOLS
			//
			if(protocol != null && protocol.trim().equalsIgnoreCase("ARP"))
				return process_ARP(line);
			
			//
			//dismiss if src ip is empty
			//
			if(src_ip == null || src_ip.trim().equals(""))
				return false;
			
			//
			//trim
			//
			full_uri_trimmed = this.normalize_lookup(http_request_full_uri, false);
			
			//
			//Process!
			//
			ndeSource = null;
			
			//
			//determine if new, or we should run an update
			//			
			if(SOURCE.TREE_SOURCE_NODES.containsKey(src_ip))
				ndeSource = SOURCE.TREE_SOURCE_NODES.get(src_ip);
			
			if(ndeSource == null)
			{
				ndeSource = new SOURCE(src_ip, src_mac);
				
				//set the resolution node if already complete
				//ndeSource.resolution_my_source_address = this.request_to_resolve(ndeSource, src_ip);
				
//				if(!ndeSource.is_private_non_routable_ip)
//					this.request_to_resolve_directly(ndeSource, src_ip);
				
				//added new node
				ThdWorker.refresh_jtable_protocol = true;
				added_new_node = true;
			}
			
			//
			//reset prev vale
			//
			ndeSource.reset_packet_values();
			
			//
			//UPDATE PROTOCOL - sometimes, tshark may categorize a source port as "TCP" even if the port is 443, etc. So if we get a generic TCP as the protocol, we'll try to resolve
			//					based on common port numbers
			//
			if(protocol.equalsIgnoreCase("TCP") || protocol.equalsIgnoreCase("UDP") || protocol.equals(""))
			{
				//check if we can update the protocol based on the destination port
				if(this.TREE_PROTOCOL_LOOKUP_TABLE.containsKey(packet_dst_port))
					protocol = TREE_PROTOCOL_LOOKUP_TABLE.get(packet_dst_port).trim();
				else if(this.TREE_PROTOCOL_LOOKUP_TABLE.containsKey(packet_src_port))
					protocol = TREE_PROTOCOL_LOOKUP_TABLE.get(packet_src_port).trim();
			}
			
			if(protocol.trim().equals(""))
				protocol = "unknown";
			
			if(packet_transmission_type == null || packet_transmission_type.trim().equals(""))
				packet_transmission_type = protocol;
			
			//
			//update ports
			//
			ndeSource.packet_dst_port = packet_dst_port;
			ndeSource.packet_src_port = packet_src_port;
			ndeSource.packet_transmission_type = packet_transmission_type;
			
			/*if(src_port_tcp != null && !src_port_tcp.trim().equals(""))
			{
				ndeSource.packet_src_port = src_port_tcp;
				ndeSource.packet_transmission_type = "TCP";				
			}
			else if(src_port_udp != null && !src_port_udp.trim().equals(""))
			{
				ndeSource.packet_src_port = src_port_udp;
				ndeSource.packet_transmission_type = "UDP";				
			}
			else
			{
				//both are blanks, thus, we're at the mercy of the detected protocol
				ndeSource.packet_src_port = " ";
				ndeSource.packet_transmission_type = protocol;
			}*/
			
			
			
			//
			//dst ports
			//
			/*if(dst_port_tcp != null && !dst_port_tcp.trim().equals(""))
			{
				ndeSource.packet_dst_port = dst_port_tcp;
				ndeSource.packet_transmission_type = "TCP";				
			}
			else if(dst_port_udp != null && !dst_port_udp.trim().equals(""))
			{
				ndeSource.packet_dst_port = dst_port_udp;
				ndeSource.packet_transmission_type = "UDP";				
			}
			else
			{
				//both are blanks, thus, we're at the mercy of the detected protocol
				ndeSource.packet_dst_port = " ";
				ndeSource.packet_transmission_type = protocol;
			}*/
			
			//ndeSource.update_protocol_packet(protocol); //<-- handled now in set_protocol
			
			//
			//check dst ip
			//
			dst_ip_is_private_non_routable_address = this.is_private_non_routable_ip(dst_ip);
			
			
			
			
			//
			//update values
			//
			ndeSource.last_http_request = "";
			ndeSource.packet_dns_query = "";
			
			ndeSource.set_version(version);
			ndeSource.set_sensor_name(sensor_name);
			ndeSource.set_interface_name(interface_name);
			ndeSource.set_frame_time(frame_time); 
			ndeSource.set_ip_protocol(ip_protocol); 
			ndeSource.set_src_mac(src_mac); 
			ndeSource.set_src_ip(src_ip); 
			ndeSource.set_src_port_tcp(src_port_tcp); 
			ndeSource.set_src_port_udp(src_port_udp); 
			ndeSource.set_protocol(protocol); 
			ndeSource.set_dst_mac(dst_mac); 
			ndeSource.set_dst_ip(dst_ip, resolution_to_use_in_your_search, packet_dst_port, protocol, user_agent); 
			ndeSource.set_dst_port_tcp(dst_port_tcp); 
			ndeSource.set_dst_port_udp(dst_port_udp); 
			
			ndeSource.trimmed_domain_name_request = this.normalize_lookup(dns_query, false)		;
			ndeSource.set_dns_query(dns_query, resolution_to_use_in_your_search); 
			
			ndeSource.trimmed_http_referer = this.normalize_lookup(http_referer, false);
			ndeSource.set_http_referer(http_referer, resolution_to_use_in_your_search); 
			
			if(!http_request_full_uri.equals(""))
			{
				this.process_FULL_URI(ndeSource, dst_ip, http_request_full_uri, full_uri_trimmed);
				
				ndeSource.trimmed_http_full_uri_request = this.normalize_lookup(http_request_full_uri, false);
				ndeSource.set_http_request_full_uri(http_request_full_uri, resolution_to_use_in_your_search); 
			}
			
			
			ndeSource.trimmed_http_request = this.normalize_lookup(http_request, Resolution.drop_subdomains);
			ndeSource.set_http_request(http_request); 
			
			ndeSource.set_http_cookie(http_cookie, http_request_full_uri); 
			ndeSource.set_details(details);
			
			//set virtual host (e.g. if ip address is the same, but hosts multiple aliases or domain_names
			ndeSource.trimmed_http_host_virtual = this.normalize_lookup(host_virtual, false);
			ndeSource.set_http_host(host_virtual, null);
			ndeSource.set_user_agent(user_agent, null);
			
			
			
			/*if(!http_request.trim().equals(""))
			{
				driver.sop("\n version 	 -->" + 	version 	);
				driver.sop("	sensor_name 	 -->" + 	sensor_name 	);
				driver.sop("	interface_name 	 -->" + 	interface_name 	);
				driver.sop("	frame_time 	 -->" + 	frame_time 	);
				driver.sop("	ip_protocol 	 -->" + 	ip_protocol 	);
				driver.sop("	src_mac 	 -->" + 	src_mac 	);
				driver.sop("	src_ip 	 -->" + 	src_ip 	);
				driver.sop("	src_port_tcp 	 -->" + 	src_port_tcp 	);
				driver.sop("	src_port_udp 	 -->" + 	src_port_udp 	);
				driver.sop("	protocol 	 -->" + 	protocol 	);
				driver.sop("	dst_mac 	 -->" + 	dst_mac 	);
				driver.sop("	dst_ip 	 -->" + 	dst_ip 	);
				driver.sop("	dst_port_tcp 	 -->" + 	dst_port_tcp 	);
				driver.sop("	dst_port_udp 	 -->" + 	dst_port_udp 	);
				driver.sop("	dns_query 	 -->" + 	dns_query 	);
				driver.sop("	http_referer 	 -->" + 	http_referer 	);
				driver.sop("	http_request_full_uri	 -->" + 	http_request_full_uri	);
				driver.sop("	full_uri_trimmed	 -->" + 	full_uri_trimmed	);
				driver.sop("	http_request 	 -->" + 	http_request 	);
				driver.sop("	http_cookie 	 -->" + 	http_cookie 	);
				driver.sop("	details 	 -->" + 	details 	);
				driver.sop("	host(virtual) 	 -->" + 	this.host_virtual 	);
				driver.sop("	user_agent 	 -->" + 	user_agent 	);
			}*/
			
			update_full_uri_again(ndeSource, src_ip, dst_ip, http_request_full_uri, full_uri_trimmed);
			
			//
			//CHECK SITNATURES
			//
			CHECK_SIGNATURES(ndeSource, http_request_full_uri);
			
			//
			//CHECK DNS PROTOCOL
			//
			if(protocol != null && protocol.trim().equalsIgnoreCase("dns"))
				process_DNS_packet(ndeSource, src_ip, dst_ip, dst_mac, dns_query, details);
			
			
			//
			//LOG
			//
			if(log != null)
				log.log_directly(line);
			
			//
			//Check GEO Location - Source
			//
			/*if(GEO_Location.GEO_RESOLUTION_ENABLED && ndeSource != null && !ndeSource.is_private_non_routable_ip && !GEO_Location.TREE_GEO_LOCATION.containsKey(src_ip) && !GEO_Location.TREE_NOT_FOUND.containsKey(src_ip))
			{
				//neither tree has the dst ip address, request for resolution
				GEO_Location geo = new GEO_Location(src_ip);
			}
			
			//
			//Check GEO Location - Destination
			//
			if(GEO_Location.GEO_RESOLUTION_ENABLED && !dst_ip_is_private_non_routable_address && !GEO_Location.TREE_GEO_LOCATION.containsKey(dst_ip) && !GEO_Location.TREE_NOT_FOUND.containsKey(dst_ip))
			{
				//neither tree has the dst ip address, request for resolution
				GEO_Location geo = new GEO_Location(dst_ip);
			}*/
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "parse", e);
		}
		
		return false;
	}
	
	/**
	 * updating a dns name with the dst ip isn't working as expected, so come here to ensure we have the right names updated..
	 * @param src_ip
	 * @param dst_ip
	 * @param full_uri
	 * @param trimmed_uri
	 * @return
	 */
	public boolean update_full_uri_again(SOURCE ndeSource, String src_ip, String dst_ip, String full_uri, String trimmed_uri)
	{
		try
		{
			if(trimmed_uri == null || dst_ip == null)
				return false;
			
			if(ndeSource == null)
				return false;
			
			if(!ndeSource.is_private_non_routable_ip)
				return false;
			
			trimmed_uri = trimmed_uri.trim();
			dst_ip = dst_ip.trim();
			
			if(trimmed_uri.equalsIgnoreCase(dst_ip))
				return false;
			
			if(trimmed_uri.equals("") || dst_ip.equals(""))
				return false;			
					
			resolution_to_use_in_your_search = null;
			
			//check if we've seen it before	
			if(Resolution.TREE_RESOURCE.containsKey(dst_ip))
			{
				resolution_to_use_in_your_search = Resolution.TREE_RESOURCE.get(dst_ip);
				
				if(resolution_to_use_in_your_search != null)
				{
					resolution_to_use_in_your_search.add_dns_query_name(trimmed_uri);
				}
			}
			else if(Resolution.TREE_RESOURCE.containsKey(trimmed_uri))
			{
				resolution_to_use_in_your_search = Resolution.TREE_RESOURCE.get(trimmed_uri);
				
				if(resolution_to_use_in_your_search != null)
				{
					resolution_to_use_in_your_search.add_dns_response_address(dst_ip);
				}
			}
			
			if(resolution_to_use_in_your_search == null)
			{
				//create new resolution
				resolution_to_use_in_your_search = new Resolution(trimmed_uri, ndeSource);
				resolution_to_use_in_your_search.add_dns_response_address(dst_ip);				
			}
		
			
			//ensure we have the right linkage
			if(!Resolution.TREE_RESOURCE.containsKey(dst_ip))
				Resolution.TREE_RESOURCE.put(dst_ip, resolution_to_use_in_your_search);
			if(!Resolution.TREE_RESOURCE.containsKey(trimmed_uri))
				Resolution.TREE_RESOURCE.put(trimmed_uri, resolution_to_use_in_your_search);
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "update_full_uri_again", e);
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
			if(log_dns == null)
			{
				log_dns = new Log("parser/dns/",  "dns_query_response", 250, 999999999);
				log_dns.OVERRIDE_LOGGING_ENABLED = true;
			}
			
			log_dns.log_directly(domain_name + "\t" + dst_ip);
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "log_dns", e);
		}
		
		return false;
	}
	
	/**
	 * this lets us know that the trimmed subdomain from the full uir request, if we have a valid dst ip, then link the domain name to the destination ip address
	 * @param ndeSource
	 * @param dst_ip
	 * @param full_uri
	 * @param full_uri_trimmed
	 * @return
	 */
	public boolean process_FULL_URI(SOURCE ndeSource, String dst_ip, String full_uri, String full_uri_trimmed)
	{
		try
		{
			if(full_uri == null || full_uri.trim().equals(""))
				return false;
			
			
			
			//
			//Get the Destination Resource
			//
			if(Resolution.TREE_RESOURCE.containsKey(full_uri_trimmed))
			{
				resolution_to_use_in_your_search = Resolution.TREE_RESOURCE.get(full_uri_trimmed);
				
				//link uri to dst_ip if applicable
				if(resolution_to_use_in_your_search != null && !Resolution.TREE_RESOURCE.containsKey(dst_ip))
				{
					Resolution.TREE_RESOURCE.put(dst_ip, resolution_to_use_in_your_search);
					
					//new IP
					try	{	resolution_to_use_in_your_search.add_dns_response_address(dst_ip);	}catch(Exception e){}
					
					//resolve
					//this.request_to_resolve_directly(ndeSource, dst_ip);
					
					//
					//log_dns
					//
					//log_dns(full_uri_trimmed, dst_ip);
					
					driver.directive("New IP Address [" + dst_ip + "] has been linked to domain [" + full_uri_trimmed + "]");
				}
			}
			
			//peradventure the tree doesn't have full_uri_trimmed, but it does have the dst_ip, then link the request to the ip 
			if(resolution_to_use_in_your_search == null && Resolution.TREE_RESOURCE.containsKey(dst_ip))
			{
				resolution_to_use_in_your_search = Resolution.TREE_RESOURCE.get(dst_ip);
				
				//link uri to dst_ip if applicable
				if(resolution_to_use_in_your_search != null && !Resolution.TREE_RESOURCE.containsKey(full_uri_trimmed))
				{
					Resolution.TREE_RESOURCE.put(full_uri_trimmed, resolution_to_use_in_your_search);
					
					//new IP
					try	{	resolution_to_use_in_your_search.add_dns_query_name(full_uri_trimmed);	}catch(Exception e){}
					
					//resolve
					//this.request_to_resolve_directly(ndeSource, full_uri_trimmed);
					
					//
					//log_dns
					//
					//log_dns(full_uri_trimmed, dst_ip);
				}
			}
			
			//create new resolution all entirely if needed
			if(resolution_to_use_in_your_search == null && !dst_ip.equals(""))
			{
				//instantiate
				resolution_to_use_in_your_search = new Resolution(full_uri_trimmed, ndeSource);
				resolution_to_use_in_your_search.add_dns_response_address(dst_ip);
								
				
				//link to uri if applicable
				if(!Resolution.TREE_RESOURCE.containsKey(dst_ip))
				{
					Resolution.TREE_RESOURCE.put(dst_ip, resolution_to_use_in_your_search);
					
					//resolve
					//this.request_to_resolve_directly(ndeSource, full_uri_trimmed);
				}				
				
			}
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "process_full_uri", e);
		}
		
		return false;
	}
	
	public boolean process_no_such_name_dns_response(SOURCE ndeSource, String src, String dst, String dst_mac, String dns_query, String details)
	{
		try
		{
			//a dns query failed, however, let's still capture this request and link it to the appropriate node
			
			if(this.is_private_non_routable_ip(dst))
			{
				SOURCE ndeDestination = null;
				
				if(SOURCE.TREE_SOURCE_NODES.containsKey(dst))
					ndeDestination = SOURCE.TREE_SOURCE_NODES.get(dst);
								
				if(ndeDestination == null)
					ndeDestination = new SOURCE(dst, dst_mac);
				
				//set the dns request, and update the link as well
				ndeDestination.trimmed_domain_name_request = this.normalize_lookup(dns_query, false);
				ndeDestination.set_dns_query(dns_query, null);
				ndeDestination.set_protocol("DNS");
				
				Resolution resource = null;
				
				if(Resolution.TREE_RESOURCE.containsKey(dns_query))
					resource = Resolution.TREE_RESOURCE.get(dns_query);				
				
				if(resource != null)
				{
					resource.link_requestor(ndeDestination);
				}
				else
				{
					resource = new Resolution(dns_query, ndeDestination);					
				}
			}
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "process_no_such_name_dns_response", e);
		}
		
		return false;
	}
	
	/**
	 * Based on the switch, we can see the host system interacting with the router for DNS requests.  however, when there's another system, we may sometimes only see the router
	 * sending DNS responses back to the system, but never the system sending various DNS requests (due to switching)... So here, if ever we see a DNS response, 
	 * let's ensure both the source (at times the router) and the destination (at times the original system that sent the request) are matched with the dns request 
	 * @param ndeSource
	 * @return
	 */
	public boolean process_DNS_packet(SOURCE ndeSource, String src, String dst, String dst_mac, String dns_query, String details)
	{
		try
		{
			if(details == null || details.trim().equals(""))
				return false;
			
			if(dns_query.toLowerCase().startsWith("https://"))
				dns_query = dns_query.substring(8);
			if(dns_query.toLowerCase().startsWith("http://"))
				dns_query = dns_query.substring(7);
			if(dns_query.toLowerCase().startsWith("www1."))
				dns_query = dns_query.substring(5);
			if(dns_query.toLowerCase().startsWith("www95."))
				dns_query = dns_query.substring(6);
			if(dns_query.toLowerCase().startsWith("www3."))
				dns_query = dns_query.substring(5);
			if(dns_query.toLowerCase().startsWith("ww3."))
				dns_query = dns_query.substring(4);
			if(dns_query.toLowerCase().startsWith("www."))
				dns_query = dns_query.substring(4);
			
			//only proceed if we have a DNS query response
			if(!details.toLowerCase().contains("standard query response"))
				return false;
			
			if(details.toLowerCase().contains("no such name"))
				return process_no_such_name_dns_response(ndeSource, src, dst, dst_mac, dns_query, details);
			
			if(details.toLowerCase().contains("server failure"))
				return false;			
			
			
			//ASSUMPTION - THE ip address is the last value in the response
			//process 1.0	Themis NetSensor_1516849480964	Local Area Connection	Jan 24, 2018 20:16:06.849071000 Mountain Standard Time	17	c8:d3:a3:59:7b:f4	192.168.0.1		53	DNS	00:50:56:38:87:76	192.168.0.106		63581	p.adsymptotic.com					Standard query response 0x50f6  CNAME p-jp-awse-1529798244.us-east-1.elb.amazonaws.com A 52.203.123.67 A 34.193.176.145 A 34.202.179.243 A 34.194.147.124 A 52.200.15.156 A 34.206.162.121 A 52.2.131.164 A 54.82.158.42
			array = details.split(" A ");
			
			if(array == null || array.length < 1)
				return false;
			
			for(String response : array)
			{
				
				//Standard query response 0x8175
				if(response.toLowerCase().contains("response") && response.toLowerCase().contains("standard"))
					continue;
				
				//dns_query_response_value = array[array.length-1];
				dns_query_response_value = response;
				
				//note, we sometimes get: 1.0	Themis NetSensor_1518459985112	Wireless Network Connection	Feb 12, 2018 12:27:29.919752000 Central Standard Time	17	f4:5c:89:bf:1c:29	10.127.47.235		5353	MDNS	01:00:5e:00:00:fb	224.0.0.251		5353						Standard query response 0x0000 TXT PTR Laptop 2015._companion-link._tcp.local AAAA, cache flush fe80::1c82:23e6:39ed:517b A, cache flush 10.127.47.235 TXT, cache flush SRV, cache flush 0 0 64679 Laptop-2015.local NSEC, cache flush Laptop-2015.local NSEC, cache flush Laptop 2015._companion-link._tcp.local		
				//Standard query response 0x0000 TXT PTR Laptop 2015._companion-link._tcp.local AAAA, cache flush fe80::1c82:23e6:39ed:517b A, cache flush 10.127.47.235 TXT, cache flush SRV, cache flush 0 0 64679 Laptop-2015.local NSEC, cache flush Laptop-2015.local NSEC, cache flush Laptop 2015._companion-link._tcp.local
				
				//1.0	Themis NetSensor_1518459985112	Wireless Network Connection	Feb 12, 2018 12:30:58.422230000 Central Standard Time	17	24:b6:57:25:7b:50	8.8.8.8		53	DNS	68:5d:43:70:c5:b5	10.127.45.176		58667	www.excite.com					Standard query response 0xba22 A www.excite.com CNAME www95.excite.com A 74.113.233.95		
				//www.excite.com					Standard query response 0xba22 A www.excite.com CNAME www95.excite.com A 74.113.233.95		
				//thus, text could be included in the response, so here, we will reject all responses that are not in ipv4 mode
				
				try
				{
					array_octet = dns_query_response_value.trim().split("\\.");
					
					for(String octet : array_octet)
						Integer.parseInt(octet.trim());
				}
				catch(Exception e)
				{
					//it failed, just continue from here and reject the input
					continue;
				}
				
				//driver.directive("qry: " + dns_query + "  [" + details + "] -- dns_query_response_value -->" + dns_query_response_value);
				
				if(log_dns == null)
				{
					log_dns = new Log("parser/dns/",  "dns_query_response", 250, 999999999);
					log_dns.OVERRIDE_LOGGING_ENABLED = true;
				}
				
//if(!Resolution.TREE_RESOURCE.containsKey(dns_query_response_value))				
//log_dns.log_directly(dns_query + "\t" + dns_query_response_value);
				
				//so at this point, we have a source, a destination, query, and the query response, update the network accordingly
				if(this.is_private_non_routable_ip(dst))
				{
					SOURCE ndeDestination = null;
					
					if(SOURCE.TREE_SOURCE_NODES.containsKey(dst))
						ndeDestination = SOURCE.TREE_SOURCE_NODES.get(dst);
									
					if(ndeDestination == null)
						ndeDestination = new SOURCE(dst, dst_mac);
					
					//set the dns request, and update the link as well
					ndeDestination.trimmed_domain_name_request = this.normalize_lookup(dns_query, false);
					ndeDestination.set_dns_query(dns_query, null);
					ndeDestination.set_protocol("DNS");
					
					Resolution resource = null;
					
					if(Resolution.TREE_RESOURCE.containsKey(dns_query))
						resource = Resolution.TREE_RESOURCE.get(dns_query);				
					
					if(resource != null)
					{
						resource.link_requestor(ndeDestination);
					}
					else
					{
						resource = new Resolution(dns_query, ndeDestination);					
					}
					
					//add query name
					resource.add_dns_query_name(dns_query);
					
					//add the resource's ip
					resource.add_dns_response_address(dns_query_response_value);
					
					//now see if we have this ip address as a source that has been seen communicating within the network
					if(SOURCE.TREE_SOURCE_NODES.containsKey(dns_query_response_value))
						SOURCE.TREE_SOURCE_NODES.get(dns_query_response_value).domain_name = dns_query;
				}
			}
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "process_DNS_packet", e);
		}
		
		return false;
	}
	
	public boolean CHECK_SIGNATURES(SOURCE ndeSource, String http_request_full_uri)
	{
		//
		//CHECK SIGNATURE
		//
		try
		{
			
			if(ndeSource == null)
				return false;			
			
			if(http_request_full_uri == null)
				http_request_full_uri = "";
			
			http_request_full_uri = http_request_full_uri.toLowerCase().trim();
			
			if(StandardInListener.intrface != null)
			{
				SIGNATURES = StandardInListener.intrface.jpnlSignature.jta.getText().toLowerCase().trim();
				
				if(SIGNATURES == null || SIGNATURES.trim().equals(""))
					return false;
				
				if(!SIGNATURES.equals(""))
				{
					//split by end of line
					ARR_SIGNATURES = SIGNATURES.split("\n");
					
					if(ARR_SIGNATURES == null || ARR_SIGNATURES.length < 1)
						ARR_SIGNATURES = SIGNATURES.split(",");
					if(ARR_SIGNATURES == null || ARR_SIGNATURES.length < 1)
						ARR_SIGNATURES = SIGNATURES.split(";");
					if(ARR_SIGNATURES == null || ARR_SIGNATURES.length < 1)
						ARR_SIGNATURES = SIGNATURES.split("\t");
					if(ARR_SIGNATURES == null || ARR_SIGNATURES.length < 1)
						ARR_SIGNATURES = new String[]{SIGNATURES};
					
					for(String signature : ARR_SIGNATURES)
					{
						if((ndeSource.getDataViewInformation("\t", false).toLowerCase().contains(signature) || (!http_request_full_uri.trim().equals("") && http_request_full_uri.contains(signature))) && !ndeSource.ALERT_DATABASE.containsKey(signature))
						{
							//
							//time stamp
							//
							curr_time = driver.time.getTime_Current_hyphenated_with_seconds("-");
							
							//
							//ALERT!!!
							//
							ndeSource.alert_indicator = "*";
							ndeSource.ALERT_DATABASE.put(signature, curr_time + "  -  " + ndeSource.getDataViewInformation("\t ", false).replaceAll("\n", ""));
							
							//
							//WRITE TO DISK
							//
							if(ALERT == null)
							{
								ALERT = new Log("parser/ALERT/",  "alert", 250, 999999999);
								ALERT.OVERRIDE_LOGGING_ENABLED = true;
								ALERT.log_directly("SOURCE" + " \t" + "TIME" + "\t" + "DETECTION_SYSTEM" + " \t" + "SIGNATURE" + " \t" + "DETAILS");
							}
							
							
							ALERT.log_directly(this.src_ip + " \t" + curr_time + "\t" + "user_signature" + " \t" + signature + " \t" + ndeSource.ALERT_DATABASE.get(signature));
							
							//
							//NOTIFY
							//
							StandardInListener.intrface.jtbl_ALERTS.addRow(new String [] {this.src_ip, curr_time, "user_signature", signature, ndeSource.ALERT_DATABASE.get(signature)});
							StandardInListener.intrface.jtbl_ALERTS.jlblNumRows.setText("" + StandardInListener.intrface.jtbl_ALERTS.jtblMyJTbl.getRowCount());
							
							//
							//SOUND!
							//
							//driver.sound.play(ThreadSound.url_alert);
							
						}
					}
				}
			}
			
			return true;
		}
		catch(Exception e)
		{
			System.out.println("Skipping Alert Signature in Parser" );
		}
		
		return false;
	}
	
	public String reverse_dns(String request)
	{
		try
		{
			if(request == null || request.trim().equals(""))
				return request;
			
			request = request.trim();
			
			if(this.is_private_non_routable_ip(request))
				return request;
			
			driver.directive("1 -- " + request);
			//ensure we have an IP address
			array_ip = request.split("\\.");
			
			if(array_ip == null || array_ip.length != 4)
				return request;
			driver.directive("2 -- " + request);
			octet_1 = Integer.parseInt(array_ip[0].trim());
			octet_2 = Integer.parseInt(array_ip[1].trim());
			octet_3 = Integer.parseInt(array_ip[2].trim());
			octet_4 = Integer.parseInt(array_ip[3].trim());
			
			//made it here, we're possibly looking at an ip address
			name_server = InetAddress.getByName(request).getCanonicalHostName();
			inet_address = InetAddress.getByName(request).getCanonicalHostName();
			
			driver.directive("Name and address -->" + InetAddress.getByName(request));
			
			if(name_server == null || name_server.trim().equalsIgnoreCase("null"))
				return request;
			
			name_server = name_server.trim();
			
			//now attempt to perform nslookup on this
			
			driver.directive("getCanonicalHostName -->"+InetAddress.getByName(request).getCanonicalHostName());
			
			//
			///
			//Solo, continue from here next time, create better routine for reverse dns lookup for domain name
			//
			//
			//
			
			if(inet_address == null || inet_address.equalsIgnoreCase("null"))
				return request;
			
			if(inet_address.startsWith("/"))
				inet_address = inet_address.substring(1);
			
						
			driver.directive("3 -- " + request);
			return inet_address;
		}
		catch(Exception e)
		{
			//driver.eop(myClassName, "reverse_dns", e);
		}
		
		return request;
	}
	
	public Resolution DEPRECATED_request_to_resolve(SOURCE source, String request)
	{
		try
		{
			if(request == null || request.trim().equals(""))
				return null;
			
			request = request.toLowerCase().trim();
			
			//convert the request to trim away URL and Sub-Domains
			request = this.normalize_lookup(request, false);
			
			//first, ensure we don't already have a resolution for the request
			if(Resolution.TREE_RESOURCE.containsKey(request))
			{
				//previous resolution request exists, link this node to it
				Resolution resolution = Resolution.TREE_RESOURCE.get(request);
				
				//link this source to the resolution
				resolution.link_requestor(source);				
				
				return resolution;
			}						
			
			//else, create the new resolution 
			Resolution resolution = new Resolution(request, source);
			
			//store the trimmed request
			source.trimmed_domain_name_request = request;
			
//			//determine if source is a private non-routable ip
//			if(is_private_non_routable_ip(src_ip) && ndeSource != null)
//			{
//				ndeSource.is_private_non_routable_ip = true;
//				//resolution.is_private_non_routable_ip = true;
//			}		
//			
			
			
			if(ndeSource != null)
				sop("Sending resolution for [" + request + "] from [" + ndeSource.src_ip + "]");
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
			
			//send this object back as one we'll update when the resolution data comes in
			return resolution;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "request_to_resolve", e, true);
		}
		
		return null;
	}
	
	
	
	public String normalize_lookup(String lookup, boolean remove_subdomains)
	{
		try
		{
			if(lookup == null)
				return "";
			
			lookup = lookup.trim();
			
			if(lookup.toLowerCase().startsWith("https://"))
				lookup = lookup.substring(8).trim();
			if(lookup.toLowerCase().startsWith("http://"))
				lookup = lookup.substring(7).trim();
			if(lookup.toLowerCase().startsWith("www95."))
				lookup = lookup.substring(6);
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
				this.array_ip = lookup.split("\\/");				
				
				if(array_ip[0] != null && !array_ip[0].trim().equals(""))
					lookup = array_ip[0].trim();
				else if(array_ip.length > 1 && array_ip[2] != null && !array_ip[2].trim().equals(""))
					lookup = array_ip[0].trim();				
			}
			
			lookup = lookup.replaceAll("\\*", "");
			
			
			//drop subdomains
			if(remove_subdomains)
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
			
			lookup = lookup.trim();			
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "normalize_lookup", e, true);
		}
		
		return lookup;
	}
	
	public Resolution request_to_resolve_directly(SOURCE source, String request)
	{
		try
		{
			if(request == null || request.trim().equals(""))
				return null;
			
			request = request.toLowerCase().trim();
			
			//convert the request to trim away URL and Sub-Domains
			//request = this.normalize_lookup(request, false);
			
			Resolution resolution = null;
			//first, ensure we don't already have a resolution for the request
			if(Resolution.TREE_RESOURCE.containsKey(request))
			{
				//previous resolution request exists, link this node to it
				resolution = Resolution.TREE_RESOURCE.get(request);
				
				//link this source to the resolution
				resolution.link_requestor(source);				
				
				//return resolution;
			}	
			else //else, create the new resolution
				resolution = new Resolution(request, source);			
			
			//store the trimmed request
			//source.trimmed_domain_name_request = request;
			
//			//determine if source is a private non-routable ip
//			if(is_private_non_routable_ip(src_ip) && ndeSource != null)
//			{
//				ndeSource.is_private_non_routable_ip = true;
//				//resolution.is_private_non_routable_ip = true;
//			}		
			
			if(ndeSource != null)
				sop("Sending resolution for [" + request + "] from [" + ndeSource.src_ip + "]");
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
			
			//send this object back as one we'll update when the resolution data comes in
			return resolution;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "request_to_resolve", e, true);
		}
		
		return null;
	}
	
	public boolean resolve_inet_address(String address)
	{
		try
		{
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "resolve_inet_address", e);
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
			
			
						
			try
			{
				array_ip = ip.split("\\.");
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
	
	
	
	public boolean populate_protocol_lookup_table()
	{
		try
		{
			TREE_PROTOCOL_LOOKUP_TABLE.put("7", "ECHO");
			TREE_PROTOCOL_LOOKUP_TABLE.put("19", "CHARGEN");
			TREE_PROTOCOL_LOOKUP_TABLE.put("20", "FTP - DATA");
			TREE_PROTOCOL_LOOKUP_TABLE.put("21", "FTP - CONTROL");
			TREE_PROTOCOL_LOOKUP_TABLE.put("22", "SSH/SCP");
			TREE_PROTOCOL_LOOKUP_TABLE.put("23", "TELNET");
			TREE_PROTOCOL_LOOKUP_TABLE.put("25", "SMTP");
			TREE_PROTOCOL_LOOKUP_TABLE.put("42", "WINS REPLICATION");
			TREE_PROTOCOL_LOOKUP_TABLE.put("43", "WHOIS");
			TREE_PROTOCOL_LOOKUP_TABLE.put("49", "TACACS");
			TREE_PROTOCOL_LOOKUP_TABLE.put("53", "DNS");
			TREE_PROTOCOL_LOOKUP_TABLE.put("67", "DHCP/BOOTP");
			TREE_PROTOCOL_LOOKUP_TABLE.put("68", "DHCP/BOOTP");
			TREE_PROTOCOL_LOOKUP_TABLE.put("69", "TFTP");
			TREE_PROTOCOL_LOOKUP_TABLE.put("70", "GOPHER");
			TREE_PROTOCOL_LOOKUP_TABLE.put("79", "FINGER");
			TREE_PROTOCOL_LOOKUP_TABLE.put("80", "HTTP");
			TREE_PROTOCOL_LOOKUP_TABLE.put("88", "KERBEROS");
			TREE_PROTOCOL_LOOKUP_TABLE.put("102", "MS EXCHANGE");
			TREE_PROTOCOL_LOOKUP_TABLE.put("110", "POP3");
			TREE_PROTOCOL_LOOKUP_TABLE.put("113", "IDENT");
			TREE_PROTOCOL_LOOKUP_TABLE.put("119", "NNTP (USENET)");
			TREE_PROTOCOL_LOOKUP_TABLE.put("123", "NTP");
			TREE_PROTOCOL_LOOKUP_TABLE.put("135", "MICROSOFT RPC");
			TREE_PROTOCOL_LOOKUP_TABLE.put("137", "NETBIOS - NAME SERVICE");
			TREE_PROTOCOL_LOOKUP_TABLE.put("138", "NETBIOS - DATAGRAM SERVICE");
			TREE_PROTOCOL_LOOKUP_TABLE.put("139", "NETBIOS - SESSION SERVICE");
			TREE_PROTOCOL_LOOKUP_TABLE.put("143", "IMAP4");
			TREE_PROTOCOL_LOOKUP_TABLE.put("161", "SNMP");
			TREE_PROTOCOL_LOOKUP_TABLE.put("162", "SNMP - TRAP");
			TREE_PROTOCOL_LOOKUP_TABLE.put("177", "XDMCP");
			TREE_PROTOCOL_LOOKUP_TABLE.put("179", "BGP");
			TREE_PROTOCOL_LOOKUP_TABLE.put("201", "APPLETALK");
			TREE_PROTOCOL_LOOKUP_TABLE.put("264", "BGMP");
			TREE_PROTOCOL_LOOKUP_TABLE.put("318", "TSP");
			TREE_PROTOCOL_LOOKUP_TABLE.put("381", "HP OPENVIEW");
			TREE_PROTOCOL_LOOKUP_TABLE.put("382", "HP OPENVIEW");
			TREE_PROTOCOL_LOOKUP_TABLE.put("383", "HP OPENVIEW");
			TREE_PROTOCOL_LOOKUP_TABLE.put("389", "LDAP");
			TREE_PROTOCOL_LOOKUP_TABLE.put("411", "DIRECT CONNECT");
			TREE_PROTOCOL_LOOKUP_TABLE.put("412", "DIRECT CONNECT");
			TREE_PROTOCOL_LOOKUP_TABLE.put("443", "TLS");
			TREE_PROTOCOL_LOOKUP_TABLE.put("445", "SMB - MICROSOFT DS");
			TREE_PROTOCOL_LOOKUP_TABLE.put("464", "KERBEROS");
			TREE_PROTOCOL_LOOKUP_TABLE.put("465", "SMTP OVER SSL");
			TREE_PROTOCOL_LOOKUP_TABLE.put("497", "RETROSPECT");
			TREE_PROTOCOL_LOOKUP_TABLE.put("500", "ISAKMP");
			TREE_PROTOCOL_LOOKUP_TABLE.put("512", "REXEC");
			TREE_PROTOCOL_LOOKUP_TABLE.put("513", "RLOGIN");
			TREE_PROTOCOL_LOOKUP_TABLE.put("514", "SYSLOG");
			TREE_PROTOCOL_LOOKUP_TABLE.put("515", "LPD/LPR");
			TREE_PROTOCOL_LOOKUP_TABLE.put("520", "RIP");
			TREE_PROTOCOL_LOOKUP_TABLE.put("521", "RIPNG (IPV6)");
			TREE_PROTOCOL_LOOKUP_TABLE.put("540", "UUCP");
			TREE_PROTOCOL_LOOKUP_TABLE.put("554", "RTSP");
			TREE_PROTOCOL_LOOKUP_TABLE.put("546", "DHCPV6");
			TREE_PROTOCOL_LOOKUP_TABLE.put("547", "DHCPV6");
			TREE_PROTOCOL_LOOKUP_TABLE.put("560", "RMONITOR");
			TREE_PROTOCOL_LOOKUP_TABLE.put("563", "NNTP OVER SSL");
			TREE_PROTOCOL_LOOKUP_TABLE.put("587", "SMTP");
			TREE_PROTOCOL_LOOKUP_TABLE.put("591", "FILEMAKER");
			TREE_PROTOCOL_LOOKUP_TABLE.put("593", "MICROSOFT DCOM");
			TREE_PROTOCOL_LOOKUP_TABLE.put("631", "INTERNET PRINTING");
			TREE_PROTOCOL_LOOKUP_TABLE.put("636", "LDAP OVER SSL");
			TREE_PROTOCOL_LOOKUP_TABLE.put("639", "MSDP (PIM)");
			TREE_PROTOCOL_LOOKUP_TABLE.put("646", "LDP (MPLS)");
			TREE_PROTOCOL_LOOKUP_TABLE.put("691", "MS EXCHANGE");
			TREE_PROTOCOL_LOOKUP_TABLE.put("860", "ISCSI");
			TREE_PROTOCOL_LOOKUP_TABLE.put("873", "RSYNC");
			TREE_PROTOCOL_LOOKUP_TABLE.put("902", "VMWARE SERVER");
			TREE_PROTOCOL_LOOKUP_TABLE.put("989", "FTP OVER SSL");
			TREE_PROTOCOL_LOOKUP_TABLE.put("990", "FTP OVER SSL");
			TREE_PROTOCOL_LOOKUP_TABLE.put("993", "IMAP4 OVER SSL");
			TREE_PROTOCOL_LOOKUP_TABLE.put("995", "POP3 OVER SSL");
			TREE_PROTOCOL_LOOKUP_TABLE.put("1025", "MICROSOFT RPC");
			TREE_PROTOCOL_LOOKUP_TABLE.put("1026", "WINDOWS MESSENGER");
			TREE_PROTOCOL_LOOKUP_TABLE.put("1027", "WINDOWS MESSENGER");
			TREE_PROTOCOL_LOOKUP_TABLE.put("1028", "WINDOWS MESSENGER");
			TREE_PROTOCOL_LOOKUP_TABLE.put("1029", "WINDOWS MESSENGER");
			TREE_PROTOCOL_LOOKUP_TABLE.put("1080", "SOCKS PROXY");
			TREE_PROTOCOL_LOOKUP_TABLE.put("1080", "MYDOOM");
			TREE_PROTOCOL_LOOKUP_TABLE.put("1194", "OPENVPN");
			TREE_PROTOCOL_LOOKUP_TABLE.put("1214", "KAZAA");
			TREE_PROTOCOL_LOOKUP_TABLE.put("1241", "NESSUS");
			TREE_PROTOCOL_LOOKUP_TABLE.put("1311", "DELL OPENMANAGE");
			TREE_PROTOCOL_LOOKUP_TABLE.put("1337", "WASTE");
			TREE_PROTOCOL_LOOKUP_TABLE.put("1433", "MICROSOFT SQL");
			TREE_PROTOCOL_LOOKUP_TABLE.put("1434", "MICROSOFT SQL");
			TREE_PROTOCOL_LOOKUP_TABLE.put("1512", "WINS");
			TREE_PROTOCOL_LOOKUP_TABLE.put("1589", "CISCO VQP");
			TREE_PROTOCOL_LOOKUP_TABLE.put("1701", "L2TP");
			TREE_PROTOCOL_LOOKUP_TABLE.put("1723", "MS PPTP");
			TREE_PROTOCOL_LOOKUP_TABLE.put("1725", "STEAM");
			TREE_PROTOCOL_LOOKUP_TABLE.put("1741", "CISCOWORKS 2000");
			TREE_PROTOCOL_LOOKUP_TABLE.put("1755", "MS MEDIA SERVER");
			TREE_PROTOCOL_LOOKUP_TABLE.put("1812", "RADIUS");
			TREE_PROTOCOL_LOOKUP_TABLE.put("1813", "RADIUS");
			TREE_PROTOCOL_LOOKUP_TABLE.put("1863", "MSN");
			TREE_PROTOCOL_LOOKUP_TABLE.put("1900", "UPNP [SSDP] (UDP)");
			TREE_PROTOCOL_LOOKUP_TABLE.put("1985", "CISCO HSRP");
			TREE_PROTOCOL_LOOKUP_TABLE.put("2000", "CISCO SCCP");
			TREE_PROTOCOL_LOOKUP_TABLE.put("2002", "CISCO ACS");
			TREE_PROTOCOL_LOOKUP_TABLE.put("2049", "NFS");
			TREE_PROTOCOL_LOOKUP_TABLE.put("2082", "CPANEL");
			TREE_PROTOCOL_LOOKUP_TABLE.put("2083", "CPANEL");
			TREE_PROTOCOL_LOOKUP_TABLE.put("2100", "ORACLE XDB");
			TREE_PROTOCOL_LOOKUP_TABLE.put("2222", "DIRECTADMIN");
			TREE_PROTOCOL_LOOKUP_TABLE.put("2302", "HALO");
			TREE_PROTOCOL_LOOKUP_TABLE.put("2483", "ORACLE DB");
			TREE_PROTOCOL_LOOKUP_TABLE.put("2484", "ORACLE DB");
			TREE_PROTOCOL_LOOKUP_TABLE.put("2745", "BAGLE.H");
			TREE_PROTOCOL_LOOKUP_TABLE.put("2967", "SYMANTEC AV");
			TREE_PROTOCOL_LOOKUP_TABLE.put("3050", "INTERBASE DB");
			TREE_PROTOCOL_LOOKUP_TABLE.put("3074", "XBOX LIVE");
			TREE_PROTOCOL_LOOKUP_TABLE.put("3124", "HTTP PROXY");
			TREE_PROTOCOL_LOOKUP_TABLE.put("3127", "MYDOOM");
			TREE_PROTOCOL_LOOKUP_TABLE.put("3128", "HTTP PROXY");
			TREE_PROTOCOL_LOOKUP_TABLE.put("3222", "GLBP");
			TREE_PROTOCOL_LOOKUP_TABLE.put("3260", "ISCSI TARGET");
			TREE_PROTOCOL_LOOKUP_TABLE.put("3306", "MYSQL");
			TREE_PROTOCOL_LOOKUP_TABLE.put("3389", "MICROSOFT RDP");
			TREE_PROTOCOL_LOOKUP_TABLE.put("3689", "ITUNES");
			TREE_PROTOCOL_LOOKUP_TABLE.put("3690", "SUBVERSION");
			TREE_PROTOCOL_LOOKUP_TABLE.put("3724", "WORLD OF WARCRAFT");
			TREE_PROTOCOL_LOOKUP_TABLE.put("3784", "VENTRILO");
			TREE_PROTOCOL_LOOKUP_TABLE.put("3785", "VENTRILO");
			TREE_PROTOCOL_LOOKUP_TABLE.put("4333", "MSQL");
			TREE_PROTOCOL_LOOKUP_TABLE.put("4444", "BLASTER");
			TREE_PROTOCOL_LOOKUP_TABLE.put("4664", "GOOGLE DESKTOP");
			TREE_PROTOCOL_LOOKUP_TABLE.put("4672", "EMULE");
			TREE_PROTOCOL_LOOKUP_TABLE.put("4899", "RADMIN");
			TREE_PROTOCOL_LOOKUP_TABLE.put("5000", "UPNP [SSDP] (TCP)");
			TREE_PROTOCOL_LOOKUP_TABLE.put("5001", "SLINGBOX");
			TREE_PROTOCOL_LOOKUP_TABLE.put("5001", "IPERF");
			TREE_PROTOCOL_LOOKUP_TABLE.put("5004", "RTP");
			TREE_PROTOCOL_LOOKUP_TABLE.put("5005", "RTP");
			TREE_PROTOCOL_LOOKUP_TABLE.put("5050", "YAHOO! MESSENGER");
			TREE_PROTOCOL_LOOKUP_TABLE.put("5060", "SIP");
			TREE_PROTOCOL_LOOKUP_TABLE.put("5190", "AIM/ICQ");
			TREE_PROTOCOL_LOOKUP_TABLE.put("5222", "XMPP/JABBER");
			TREE_PROTOCOL_LOOKUP_TABLE.put("5223", "XMPP/JABBER");
			TREE_PROTOCOL_LOOKUP_TABLE.put("5432", "POSTGRESQL");
			TREE_PROTOCOL_LOOKUP_TABLE.put("5500", "VNC SERVER");
			TREE_PROTOCOL_LOOKUP_TABLE.put("5554", "SASSER");
			TREE_PROTOCOL_LOOKUP_TABLE.put("5631", "PCANYWHERE");
			TREE_PROTOCOL_LOOKUP_TABLE.put("5632", "PCANYWHERE");
			TREE_PROTOCOL_LOOKUP_TABLE.put("5800", "VNC OVER HTTP");
			TREE_PROTOCOL_LOOKUP_TABLE.put("5900", "VNC SERVER");
			TREE_PROTOCOL_LOOKUP_TABLE.put("6000", "X11");
			TREE_PROTOCOL_LOOKUP_TABLE.put("6001", "X11");
			TREE_PROTOCOL_LOOKUP_TABLE.put("6112", "BATTLE.NET");
			TREE_PROTOCOL_LOOKUP_TABLE.put("6129", "DAMEWARE");
			TREE_PROTOCOL_LOOKUP_TABLE.put("6257", "WINMX");
			TREE_PROTOCOL_LOOKUP_TABLE.put("6346", "GNUTELLA");
			TREE_PROTOCOL_LOOKUP_TABLE.put("6347", "GNUTELLA");
			TREE_PROTOCOL_LOOKUP_TABLE.put("6500", "GAMESPY ARCADE");
			TREE_PROTOCOL_LOOKUP_TABLE.put("6566", "SANE");
			TREE_PROTOCOL_LOOKUP_TABLE.put("6588", "ANALOGX");
			TREE_PROTOCOL_LOOKUP_TABLE.put("6665", "IRC");
			TREE_PROTOCOL_LOOKUP_TABLE.put("6666", "IRC");
			TREE_PROTOCOL_LOOKUP_TABLE.put("6667", "IRC");
			TREE_PROTOCOL_LOOKUP_TABLE.put("6668", "IRC");
			TREE_PROTOCOL_LOOKUP_TABLE.put("6669", "IRC");
			TREE_PROTOCOL_LOOKUP_TABLE.put("6679", "IRC OVER SSL");
			TREE_PROTOCOL_LOOKUP_TABLE.put("6697", "IRC OVER SSL");
			TREE_PROTOCOL_LOOKUP_TABLE.put("6699", "NAPSTER");
			TREE_PROTOCOL_LOOKUP_TABLE.put("6881", "BITTORRENT");
			TREE_PROTOCOL_LOOKUP_TABLE.put("6882", "BITTORRENT");
			TREE_PROTOCOL_LOOKUP_TABLE.put("6883", "BITTORRENT");
			TREE_PROTOCOL_LOOKUP_TABLE.put("6884", "BITTORRENT");
			TREE_PROTOCOL_LOOKUP_TABLE.put("6885", "BITTORRENT");
			TREE_PROTOCOL_LOOKUP_TABLE.put("6886", "BITTORRENT");
			TREE_PROTOCOL_LOOKUP_TABLE.put("6887", "BITTORRENT");
			TREE_PROTOCOL_LOOKUP_TABLE.put("6888", "BITTORRENT");
			TREE_PROTOCOL_LOOKUP_TABLE.put("6889", "BITTORRENT");
			TREE_PROTOCOL_LOOKUP_TABLE.put("6890", "BITTORRENT");
			TREE_PROTOCOL_LOOKUP_TABLE.put("6891", "BITTORRENT");
			TREE_PROTOCOL_LOOKUP_TABLE.put("6892", "BITTORRENT");
			TREE_PROTOCOL_LOOKUP_TABLE.put("6893", "BITTORRENT");
			TREE_PROTOCOL_LOOKUP_TABLE.put("6894", "BITTORRENT");
			TREE_PROTOCOL_LOOKUP_TABLE.put("6895", "BITTORRENT");
			TREE_PROTOCOL_LOOKUP_TABLE.put("6896", "BITTORRENT");
			TREE_PROTOCOL_LOOKUP_TABLE.put("6897", "BITTORRENT");
			TREE_PROTOCOL_LOOKUP_TABLE.put("6898", "BITTORRENT");
			TREE_PROTOCOL_LOOKUP_TABLE.put("6999", "BITTORRENT");
			TREE_PROTOCOL_LOOKUP_TABLE.put("6891", "WINDOWS LIVE");
			TREE_PROTOCOL_LOOKUP_TABLE.put("6892", "WINDOWS LIVE");
			TREE_PROTOCOL_LOOKUP_TABLE.put("6893", "WINDOWS LIVE");
			TREE_PROTOCOL_LOOKUP_TABLE.put("6894", "WINDOWS LIVE");
			TREE_PROTOCOL_LOOKUP_TABLE.put("6895", "WINDOWS LIVE");
			TREE_PROTOCOL_LOOKUP_TABLE.put("6896", "WINDOWS LIVE");
			TREE_PROTOCOL_LOOKUP_TABLE.put("6897", "WINDOWS LIVE");
			TREE_PROTOCOL_LOOKUP_TABLE.put("6898", "WINDOWS LIVE");
			TREE_PROTOCOL_LOOKUP_TABLE.put("6899", "WINDOWS LIVE");
			TREE_PROTOCOL_LOOKUP_TABLE.put("6900", "WINDOWS LIVE");
			TREE_PROTOCOL_LOOKUP_TABLE.put("6901", "WINDOWS LIVE");
			TREE_PROTOCOL_LOOKUP_TABLE.put("6970", "QUICKTIME");
			TREE_PROTOCOL_LOOKUP_TABLE.put("7212", "GHOSTSURF");
			TREE_PROTOCOL_LOOKUP_TABLE.put("7648", "CU-SEEME");
			TREE_PROTOCOL_LOOKUP_TABLE.put("7649", "CU-SEEME");
			TREE_PROTOCOL_LOOKUP_TABLE.put("8000", "INTERNET RADIO");
			TREE_PROTOCOL_LOOKUP_TABLE.put("8080", "HTTP PROXY");
			TREE_PROTOCOL_LOOKUP_TABLE.put("8086", "KASPERSKY AV");
			TREE_PROTOCOL_LOOKUP_TABLE.put("8087", "KASPERSKY AV");
			TREE_PROTOCOL_LOOKUP_TABLE.put("8118", "PRIVOXY");
			TREE_PROTOCOL_LOOKUP_TABLE.put("8200", "VMWARE SERVER");
			TREE_PROTOCOL_LOOKUP_TABLE.put("8500", "ADOBE COLDFUSION");
			TREE_PROTOCOL_LOOKUP_TABLE.put("8767", "TEAMSPEAK");
			TREE_PROTOCOL_LOOKUP_TABLE.put("8866", "BAGLE.B");
			TREE_PROTOCOL_LOOKUP_TABLE.put("9100", "HP JETDIRECT");
			TREE_PROTOCOL_LOOKUP_TABLE.put("9101", "BACULA");
			TREE_PROTOCOL_LOOKUP_TABLE.put("9102", "BACULA");
			TREE_PROTOCOL_LOOKUP_TABLE.put("9103", "BACULA");
			TREE_PROTOCOL_LOOKUP_TABLE.put("9119", "MXIT");
			TREE_PROTOCOL_LOOKUP_TABLE.put("9800", "WEBDAV");
			TREE_PROTOCOL_LOOKUP_TABLE.put("9898", "DABBER");
			TREE_PROTOCOL_LOOKUP_TABLE.put("9988", "RBOT/SPYBOT");
			TREE_PROTOCOL_LOOKUP_TABLE.put("9999", "URCHIN");
			TREE_PROTOCOL_LOOKUP_TABLE.put("10000", "WEBMIN");
			TREE_PROTOCOL_LOOKUP_TABLE.put("10000", "BACKUPEXEC");
			TREE_PROTOCOL_LOOKUP_TABLE.put("10113", "NETIQ");
			TREE_PROTOCOL_LOOKUP_TABLE.put("10114", "NETIQ");
			TREE_PROTOCOL_LOOKUP_TABLE.put("10115", "NETIQ");
			TREE_PROTOCOL_LOOKUP_TABLE.put("10116", "NETIQ");
			TREE_PROTOCOL_LOOKUP_TABLE.put("11371", "OPENPGP");
			TREE_PROTOCOL_LOOKUP_TABLE.put("12035", "SECOND LIFE");
			TREE_PROTOCOL_LOOKUP_TABLE.put("12036", "SECOND LIFE");
			TREE_PROTOCOL_LOOKUP_TABLE.put("12345", "NETBUS");
			TREE_PROTOCOL_LOOKUP_TABLE.put("13720", "NETBACKUP");
			TREE_PROTOCOL_LOOKUP_TABLE.put("13721", "NETBACKUP");
			TREE_PROTOCOL_LOOKUP_TABLE.put("14567", "BATTLEFIELD");
			TREE_PROTOCOL_LOOKUP_TABLE.put("15118", "DIPNET/ODDBOB");
			TREE_PROTOCOL_LOOKUP_TABLE.put("19226", "ADMINSECURE");
			TREE_PROTOCOL_LOOKUP_TABLE.put("19638", "ENSIM");
			TREE_PROTOCOL_LOOKUP_TABLE.put("20000", "USERMIN");
			TREE_PROTOCOL_LOOKUP_TABLE.put("24800", "SYNERGY");
			TREE_PROTOCOL_LOOKUP_TABLE.put("25999", "XFIRE");
			TREE_PROTOCOL_LOOKUP_TABLE.put("27015", "HALF-LIFE");
			TREE_PROTOCOL_LOOKUP_TABLE.put("27374", "SUB7");
			TREE_PROTOCOL_LOOKUP_TABLE.put("28960", "CALL OF DUTY");
			TREE_PROTOCOL_LOOKUP_TABLE.put("31337", "BACK ORIFICE");
			TREE_PROTOCOL_LOOKUP_TABLE.put("33434", "TRACEROUTE");
			TREE_PROTOCOL_LOOKUP_TABLE.put("47001", "WINRM");TREE_PROTOCOL_LOOKUP_TABLE.put("7", "ECHO");
			TREE_PROTOCOL_LOOKUP_TABLE.put("19", "CHARGEN");
			TREE_PROTOCOL_LOOKUP_TABLE.put("20", "FTP - DATA");
			TREE_PROTOCOL_LOOKUP_TABLE.put("21", "FTP - CONTROL");
			TREE_PROTOCOL_LOOKUP_TABLE.put("22", "SSH/SCP");
			TREE_PROTOCOL_LOOKUP_TABLE.put("23", "TELNET");
			TREE_PROTOCOL_LOOKUP_TABLE.put("25", "SMTP");
			TREE_PROTOCOL_LOOKUP_TABLE.put("42", "WINS REPLICATION");
			TREE_PROTOCOL_LOOKUP_TABLE.put("43", "WHOIS");
			TREE_PROTOCOL_LOOKUP_TABLE.put("49", "TACACS");
			TREE_PROTOCOL_LOOKUP_TABLE.put("53", "DNS");
			TREE_PROTOCOL_LOOKUP_TABLE.put("67", "DHCP/BOOTP");
			TREE_PROTOCOL_LOOKUP_TABLE.put("68", "DHCP/BOOTP");
			TREE_PROTOCOL_LOOKUP_TABLE.put("69", "TFTP");
			TREE_PROTOCOL_LOOKUP_TABLE.put("70", "GOPHER");
			TREE_PROTOCOL_LOOKUP_TABLE.put("79", "FINGER");
			TREE_PROTOCOL_LOOKUP_TABLE.put("80", "HTTP");
			TREE_PROTOCOL_LOOKUP_TABLE.put("88", "KERBEROS");
			TREE_PROTOCOL_LOOKUP_TABLE.put("102", "MS EXCHANGE");
			TREE_PROTOCOL_LOOKUP_TABLE.put("110", "POP3");
			TREE_PROTOCOL_LOOKUP_TABLE.put("113", "IDENT");
			TREE_PROTOCOL_LOOKUP_TABLE.put("119", "NNTP (USENET)");
			TREE_PROTOCOL_LOOKUP_TABLE.put("123", "NTP");
			TREE_PROTOCOL_LOOKUP_TABLE.put("135", "MICROSOFT RPC");
			TREE_PROTOCOL_LOOKUP_TABLE.put("137", "NETBIOS - NAME SERVICE");
			TREE_PROTOCOL_LOOKUP_TABLE.put("138", "NETBIOS - DATAGRAM SERVICE");
			TREE_PROTOCOL_LOOKUP_TABLE.put("139", "NETBIOS - SESSION SERVICE");
			TREE_PROTOCOL_LOOKUP_TABLE.put("143", "IMAP4");
			TREE_PROTOCOL_LOOKUP_TABLE.put("161", "SNMP");
			TREE_PROTOCOL_LOOKUP_TABLE.put("162", "SNMP - TRAP");
			TREE_PROTOCOL_LOOKUP_TABLE.put("177", "XDMCP");
			TREE_PROTOCOL_LOOKUP_TABLE.put("179", "BGP");
			TREE_PROTOCOL_LOOKUP_TABLE.put("201", "APPLETALK");
			TREE_PROTOCOL_LOOKUP_TABLE.put("264", "BGMP");
			TREE_PROTOCOL_LOOKUP_TABLE.put("318", "TSP");
			TREE_PROTOCOL_LOOKUP_TABLE.put("381", "HP OPENVIEW");
			TREE_PROTOCOL_LOOKUP_TABLE.put("382", "HP OPENVIEW");
			TREE_PROTOCOL_LOOKUP_TABLE.put("383", "HP OPENVIEW");
			TREE_PROTOCOL_LOOKUP_TABLE.put("389", "LDAP");
			TREE_PROTOCOL_LOOKUP_TABLE.put("411", "DIRECT CONNECT");
			TREE_PROTOCOL_LOOKUP_TABLE.put("412", "DIRECT CONNECT");
			TREE_PROTOCOL_LOOKUP_TABLE.put("443", "TLS");
			TREE_PROTOCOL_LOOKUP_TABLE.put("445", "MICROSOFT DS");
			TREE_PROTOCOL_LOOKUP_TABLE.put("464", "KERBEROS");
			TREE_PROTOCOL_LOOKUP_TABLE.put("465", "SMTP OVER SSL");
			TREE_PROTOCOL_LOOKUP_TABLE.put("497", "RETROSPECT");
			TREE_PROTOCOL_LOOKUP_TABLE.put("500", "ISAKMP");
			TREE_PROTOCOL_LOOKUP_TABLE.put("512", "REXEC");
			TREE_PROTOCOL_LOOKUP_TABLE.put("513", "RLOGIN");
			TREE_PROTOCOL_LOOKUP_TABLE.put("514", "SYSLOG");
			TREE_PROTOCOL_LOOKUP_TABLE.put("515", "LPD/LPR");
			TREE_PROTOCOL_LOOKUP_TABLE.put("520", "RIP");
			TREE_PROTOCOL_LOOKUP_TABLE.put("521", "RIPNG (IPV6)");
			TREE_PROTOCOL_LOOKUP_TABLE.put("540", "UUCP");
			TREE_PROTOCOL_LOOKUP_TABLE.put("554", "RTSP");
			TREE_PROTOCOL_LOOKUP_TABLE.put("546", "DHCPV6");
			TREE_PROTOCOL_LOOKUP_TABLE.put("547", "DHCPV6");
			TREE_PROTOCOL_LOOKUP_TABLE.put("560", "RMONITOR");
			TREE_PROTOCOL_LOOKUP_TABLE.put("563", "NNTP OVER SSL");
			TREE_PROTOCOL_LOOKUP_TABLE.put("587", "SMTP");
			TREE_PROTOCOL_LOOKUP_TABLE.put("591", "FILEMAKER");
			TREE_PROTOCOL_LOOKUP_TABLE.put("593", "MICROSOFT DCOM");
			TREE_PROTOCOL_LOOKUP_TABLE.put("631", "INTERNET PRINTING");
			TREE_PROTOCOL_LOOKUP_TABLE.put("636", "LDAP OVER SSL");
			TREE_PROTOCOL_LOOKUP_TABLE.put("639", "MSDP (PIM)");
			TREE_PROTOCOL_LOOKUP_TABLE.put("646", "LDP (MPLS)");
			TREE_PROTOCOL_LOOKUP_TABLE.put("691", "MS EXCHANGE");
			TREE_PROTOCOL_LOOKUP_TABLE.put("860", "ISCSI");
			TREE_PROTOCOL_LOOKUP_TABLE.put("873", "RSYNC");
			TREE_PROTOCOL_LOOKUP_TABLE.put("902", "VMWARE SERVER");
			TREE_PROTOCOL_LOOKUP_TABLE.put("989", "FTP OVER SSL");
			TREE_PROTOCOL_LOOKUP_TABLE.put("990", "FTP OVER SSL");
			TREE_PROTOCOL_LOOKUP_TABLE.put("993", "IMAP4 OVER SSL");
			TREE_PROTOCOL_LOOKUP_TABLE.put("995", "POP3 OVER SSL");
			TREE_PROTOCOL_LOOKUP_TABLE.put("1025", "MICROSOFT RPC");
			TREE_PROTOCOL_LOOKUP_TABLE.put("1026", "WINDOWS MESSENGER");
			TREE_PROTOCOL_LOOKUP_TABLE.put("1027", "WINDOWS MESSENGER");
			TREE_PROTOCOL_LOOKUP_TABLE.put("1028", "WINDOWS MESSENGER");
			TREE_PROTOCOL_LOOKUP_TABLE.put("1029", "WINDOWS MESSENGER");
			TREE_PROTOCOL_LOOKUP_TABLE.put("1080", "SOCKS PROXY");
			TREE_PROTOCOL_LOOKUP_TABLE.put("1080", "MYDOOM");
			TREE_PROTOCOL_LOOKUP_TABLE.put("1194", "OPENVPN");
			TREE_PROTOCOL_LOOKUP_TABLE.put("1214", "KAZAA");
			TREE_PROTOCOL_LOOKUP_TABLE.put("1241", "NESSUS");
			TREE_PROTOCOL_LOOKUP_TABLE.put("1311", "DELL OPENMANAGE");
			TREE_PROTOCOL_LOOKUP_TABLE.put("1337", "WASTE");
			TREE_PROTOCOL_LOOKUP_TABLE.put("1433", "MICROSOFT SQL");
			TREE_PROTOCOL_LOOKUP_TABLE.put("1434", "MICROSOFT SQL");
			TREE_PROTOCOL_LOOKUP_TABLE.put("1512", "WINS");
			TREE_PROTOCOL_LOOKUP_TABLE.put("1589", "CISCO VQP");
			TREE_PROTOCOL_LOOKUP_TABLE.put("1701", "L2TP");
			TREE_PROTOCOL_LOOKUP_TABLE.put("1723", "MS PPTP");
			TREE_PROTOCOL_LOOKUP_TABLE.put("1725", "STEAM");
			TREE_PROTOCOL_LOOKUP_TABLE.put("1741", "CISCOWORKS 2000");
			TREE_PROTOCOL_LOOKUP_TABLE.put("1755", "MS MEDIA SERVER");
			TREE_PROTOCOL_LOOKUP_TABLE.put("1812", "RADIUS");
			TREE_PROTOCOL_LOOKUP_TABLE.put("1813", "RADIUS");
			TREE_PROTOCOL_LOOKUP_TABLE.put("1863", "MSN");
			TREE_PROTOCOL_LOOKUP_TABLE.put("1985", "CISCO HSRP");
			TREE_PROTOCOL_LOOKUP_TABLE.put("2000", "CISCO SCCP");
			TREE_PROTOCOL_LOOKUP_TABLE.put("2002", "CISCO ACS");
			TREE_PROTOCOL_LOOKUP_TABLE.put("2049", "NFS");
			TREE_PROTOCOL_LOOKUP_TABLE.put("2082", "CPANEL");
			TREE_PROTOCOL_LOOKUP_TABLE.put("2083", "CPANEL");
			TREE_PROTOCOL_LOOKUP_TABLE.put("2100", "ORACLE XDB");
			TREE_PROTOCOL_LOOKUP_TABLE.put("2222", "DIRECTADMIN");
			TREE_PROTOCOL_LOOKUP_TABLE.put("2302", "HALO");
			TREE_PROTOCOL_LOOKUP_TABLE.put("2483", "ORACLE DB");
			TREE_PROTOCOL_LOOKUP_TABLE.put("2484", "ORACLE DB");
			TREE_PROTOCOL_LOOKUP_TABLE.put("2745", "BAGLE.H");
			TREE_PROTOCOL_LOOKUP_TABLE.put("2967", "SYMANTEC AV");
			TREE_PROTOCOL_LOOKUP_TABLE.put("3050", "INTERBASE DB");
			TREE_PROTOCOL_LOOKUP_TABLE.put("3074", "XBOX LIVE");
			TREE_PROTOCOL_LOOKUP_TABLE.put("3124", "HTTP PROXY");
			TREE_PROTOCOL_LOOKUP_TABLE.put("3127", "MYDOOM");
			TREE_PROTOCOL_LOOKUP_TABLE.put("3128", "HTTP PROXY");
			TREE_PROTOCOL_LOOKUP_TABLE.put("3222", "GLBP");
			TREE_PROTOCOL_LOOKUP_TABLE.put("3260", "ISCSI TARGET");
			TREE_PROTOCOL_LOOKUP_TABLE.put("3306", "MYSQL");
			TREE_PROTOCOL_LOOKUP_TABLE.put("3389", "MICROSOFT RDP");
			TREE_PROTOCOL_LOOKUP_TABLE.put("3689", "ITUNES");
			TREE_PROTOCOL_LOOKUP_TABLE.put("3690", "SUBVERSION");
			TREE_PROTOCOL_LOOKUP_TABLE.put("3724", "WORLD OF WARCRAFT");
			TREE_PROTOCOL_LOOKUP_TABLE.put("3784", "VENTRILO");
			TREE_PROTOCOL_LOOKUP_TABLE.put("3785", "VENTRILO");
			TREE_PROTOCOL_LOOKUP_TABLE.put("4333", "MSQL");
			TREE_PROTOCOL_LOOKUP_TABLE.put("4444", "BLASTER");
			TREE_PROTOCOL_LOOKUP_TABLE.put("4664", "GOOGLE DESKTOP");
			TREE_PROTOCOL_LOOKUP_TABLE.put("4672", "EMULE");
			TREE_PROTOCOL_LOOKUP_TABLE.put("4899", "RADMIN");
			TREE_PROTOCOL_LOOKUP_TABLE.put("5000", "UPNP");
			TREE_PROTOCOL_LOOKUP_TABLE.put("5001", "SLINGBOX");
			TREE_PROTOCOL_LOOKUP_TABLE.put("5001", "IPERF");
			TREE_PROTOCOL_LOOKUP_TABLE.put("5004", "RTP");
			TREE_PROTOCOL_LOOKUP_TABLE.put("5005", "RTP");
			TREE_PROTOCOL_LOOKUP_TABLE.put("5050", "YAHOO! MESSENGER");
			TREE_PROTOCOL_LOOKUP_TABLE.put("5060", "SIP");
			TREE_PROTOCOL_LOOKUP_TABLE.put("5190", "AIM/ICQ");
			TREE_PROTOCOL_LOOKUP_TABLE.put("5222", "XMPP/JABBER");
			TREE_PROTOCOL_LOOKUP_TABLE.put("5223", "XMPP/JABBER");
			TREE_PROTOCOL_LOOKUP_TABLE.put("5432", "POSTGRESQL");
			TREE_PROTOCOL_LOOKUP_TABLE.put("5500", "VNC SERVER");
			TREE_PROTOCOL_LOOKUP_TABLE.put("5554", "SASSER");
			TREE_PROTOCOL_LOOKUP_TABLE.put("5631", "PCANYWHERE");
			TREE_PROTOCOL_LOOKUP_TABLE.put("5632", "PCANYWHERE");
			TREE_PROTOCOL_LOOKUP_TABLE.put("5800", "VNC OVER HTTP");
			TREE_PROTOCOL_LOOKUP_TABLE.put("5900", "VNC SERVER");
			TREE_PROTOCOL_LOOKUP_TABLE.put("6000", "X11");
			TREE_PROTOCOL_LOOKUP_TABLE.put("6001", "X11");
			TREE_PROTOCOL_LOOKUP_TABLE.put("6112", "BATTLE.NET");
			TREE_PROTOCOL_LOOKUP_TABLE.put("6129", "DAMEWARE");
			TREE_PROTOCOL_LOOKUP_TABLE.put("6257", "WINMX");
			TREE_PROTOCOL_LOOKUP_TABLE.put("6346", "GNUTELLA");
			TREE_PROTOCOL_LOOKUP_TABLE.put("6347", "GNUTELLA");
			TREE_PROTOCOL_LOOKUP_TABLE.put("6500", "GAMESPY ARCADE");
			TREE_PROTOCOL_LOOKUP_TABLE.put("6566", "SANE");
			TREE_PROTOCOL_LOOKUP_TABLE.put("6588", "ANALOGX");
			TREE_PROTOCOL_LOOKUP_TABLE.put("6665", "IRC");
			TREE_PROTOCOL_LOOKUP_TABLE.put("6666", "IRC");
			TREE_PROTOCOL_LOOKUP_TABLE.put("6667", "IRC");
			TREE_PROTOCOL_LOOKUP_TABLE.put("6668", "IRC");
			TREE_PROTOCOL_LOOKUP_TABLE.put("6669", "IRC");
			TREE_PROTOCOL_LOOKUP_TABLE.put("6679", "IRC OVER SSL");
			TREE_PROTOCOL_LOOKUP_TABLE.put("6697", "IRC OVER SSL");
			TREE_PROTOCOL_LOOKUP_TABLE.put("6699", "NAPSTER");
			TREE_PROTOCOL_LOOKUP_TABLE.put("6881", "BITTORRENT");
			TREE_PROTOCOL_LOOKUP_TABLE.put("6882", "BITTORRENT");
			TREE_PROTOCOL_LOOKUP_TABLE.put("6883", "BITTORRENT");
			TREE_PROTOCOL_LOOKUP_TABLE.put("6884", "BITTORRENT");
			TREE_PROTOCOL_LOOKUP_TABLE.put("6885", "BITTORRENT");
			TREE_PROTOCOL_LOOKUP_TABLE.put("6886", "BITTORRENT");
			TREE_PROTOCOL_LOOKUP_TABLE.put("6887", "BITTORRENT");
			TREE_PROTOCOL_LOOKUP_TABLE.put("6888", "BITTORRENT");
			TREE_PROTOCOL_LOOKUP_TABLE.put("6889", "BITTORRENT");
			TREE_PROTOCOL_LOOKUP_TABLE.put("6890", "BITTORRENT");
			TREE_PROTOCOL_LOOKUP_TABLE.put("6891", "BITTORRENT");
			TREE_PROTOCOL_LOOKUP_TABLE.put("6892", "BITTORRENT");
			TREE_PROTOCOL_LOOKUP_TABLE.put("6893", "BITTORRENT");
			TREE_PROTOCOL_LOOKUP_TABLE.put("6894", "BITTORRENT");
			TREE_PROTOCOL_LOOKUP_TABLE.put("6895", "BITTORRENT");
			TREE_PROTOCOL_LOOKUP_TABLE.put("6896", "BITTORRENT");
			TREE_PROTOCOL_LOOKUP_TABLE.put("6897", "BITTORRENT");
			TREE_PROTOCOL_LOOKUP_TABLE.put("6898", "BITTORRENT");
			TREE_PROTOCOL_LOOKUP_TABLE.put("6999", "BITTORRENT");
			TREE_PROTOCOL_LOOKUP_TABLE.put("6891", "WINDOWS LIVE");
			TREE_PROTOCOL_LOOKUP_TABLE.put("6892", "WINDOWS LIVE");
			TREE_PROTOCOL_LOOKUP_TABLE.put("6893", "WINDOWS LIVE");
			TREE_PROTOCOL_LOOKUP_TABLE.put("6894", "WINDOWS LIVE");
			TREE_PROTOCOL_LOOKUP_TABLE.put("6895", "WINDOWS LIVE");
			TREE_PROTOCOL_LOOKUP_TABLE.put("6896", "WINDOWS LIVE");
			TREE_PROTOCOL_LOOKUP_TABLE.put("6897", "WINDOWS LIVE");
			TREE_PROTOCOL_LOOKUP_TABLE.put("6898", "WINDOWS LIVE");
			TREE_PROTOCOL_LOOKUP_TABLE.put("6899", "WINDOWS LIVE");
			TREE_PROTOCOL_LOOKUP_TABLE.put("6900", "WINDOWS LIVE");
			TREE_PROTOCOL_LOOKUP_TABLE.put("6901", "WINDOWS LIVE");
			TREE_PROTOCOL_LOOKUP_TABLE.put("6970", "QUICKTIME");
			TREE_PROTOCOL_LOOKUP_TABLE.put("7212", "GHOSTSURF");
			TREE_PROTOCOL_LOOKUP_TABLE.put("7648", "CU-SEEME");
			TREE_PROTOCOL_LOOKUP_TABLE.put("7649", "CU-SEEME");
			TREE_PROTOCOL_LOOKUP_TABLE.put("8000", "INTERNET RADIO");
			TREE_PROTOCOL_LOOKUP_TABLE.put("8080", "HTTP PROXY");
			TREE_PROTOCOL_LOOKUP_TABLE.put("8086", "KASPERSKY AV");
			TREE_PROTOCOL_LOOKUP_TABLE.put("8087", "KASPERSKY AV");
			TREE_PROTOCOL_LOOKUP_TABLE.put("8118", "PRIVOXY");
			TREE_PROTOCOL_LOOKUP_TABLE.put("8200", "VMWARE SERVER");
			TREE_PROTOCOL_LOOKUP_TABLE.put("8500", "ADOBE COLDFUSION");
			TREE_PROTOCOL_LOOKUP_TABLE.put("8767", "TEAMSPEAK");
			TREE_PROTOCOL_LOOKUP_TABLE.put("8866", "BAGLE.B");
			TREE_PROTOCOL_LOOKUP_TABLE.put("9100", "HP JETDIRECT");
			TREE_PROTOCOL_LOOKUP_TABLE.put("9101", "BACULA");
			TREE_PROTOCOL_LOOKUP_TABLE.put("9102", "BACULA");
			TREE_PROTOCOL_LOOKUP_TABLE.put("9103", "BACULA");
			TREE_PROTOCOL_LOOKUP_TABLE.put("9119", "MXIT");
			TREE_PROTOCOL_LOOKUP_TABLE.put("9800", "WEBDAV");
			TREE_PROTOCOL_LOOKUP_TABLE.put("9898", "DABBER");
			TREE_PROTOCOL_LOOKUP_TABLE.put("9988", "RBOT/SPYBOT");
			TREE_PROTOCOL_LOOKUP_TABLE.put("9999", "URCHIN");
			TREE_PROTOCOL_LOOKUP_TABLE.put("10000", "WEBMIN");
			TREE_PROTOCOL_LOOKUP_TABLE.put("10000", "BACKUPEXEC");
			TREE_PROTOCOL_LOOKUP_TABLE.put("10113", "NETIQ");
			TREE_PROTOCOL_LOOKUP_TABLE.put("10114", "NETIQ");
			TREE_PROTOCOL_LOOKUP_TABLE.put("10115", "NETIQ");
			TREE_PROTOCOL_LOOKUP_TABLE.put("10116", "NETIQ");
			TREE_PROTOCOL_LOOKUP_TABLE.put("11371", "OPENPGP");
			TREE_PROTOCOL_LOOKUP_TABLE.put("12035", "SECOND LIFE");
			TREE_PROTOCOL_LOOKUP_TABLE.put("12036", "SECOND LIFE");
			TREE_PROTOCOL_LOOKUP_TABLE.put("12345", "NETBUS");
			TREE_PROTOCOL_LOOKUP_TABLE.put("13720", "NETBACKUP");
			TREE_PROTOCOL_LOOKUP_TABLE.put("13721", "NETBACKUP");
			TREE_PROTOCOL_LOOKUP_TABLE.put("14567", "BATTLEFIELD");
			TREE_PROTOCOL_LOOKUP_TABLE.put("15118", "DIPNET/ODDBOB");
			TREE_PROTOCOL_LOOKUP_TABLE.put("19226", "ADMINSECURE");
			TREE_PROTOCOL_LOOKUP_TABLE.put("19638", "ENSIM");
			TREE_PROTOCOL_LOOKUP_TABLE.put("20000", "USERMIN");
			TREE_PROTOCOL_LOOKUP_TABLE.put("24800", "SYNERGY");
			TREE_PROTOCOL_LOOKUP_TABLE.put("25999", "XFIRE");
			TREE_PROTOCOL_LOOKUP_TABLE.put("27015", "HALF-LIFE");
			TREE_PROTOCOL_LOOKUP_TABLE.put("27374", "SUB7");
			TREE_PROTOCOL_LOOKUP_TABLE.put("28960", "CALL OF DUTY");
			TREE_PROTOCOL_LOOKUP_TABLE.put("31337", "BACK ORIFICE");
			TREE_PROTOCOL_LOOKUP_TABLE.put("33434", "TRACEROUTE");
			TREE_PROTOCOL_LOOKUP_TABLE.put("47001", "WINRM");
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "populate_protocol_lookup_table", e);
		}
		
		return false;
	}
	
	
	public boolean import_file(File fle)
	{
		try
		{
			driver.directive("\nCommencing import on file --> " + fle.getCanonicalPath());
			
			//Read each file and put onto the parsing queue
			BufferedReader brIn = new BufferedReader(new FileReader(fle));
			String line = "";
			int parser_index = 0;
			int num_lines = 0;
			
			StandardInListener.stop = false;
			
			while((line = brIn.readLine()) != null)
			{
				if(StandardInListener.stop)
				{
					driver.directive("\nSTOP COMMAND RECEIVED. Halting read action.");
					break;
				}
				
				if(Parser.list_parsers != null && Parser.list_parsers.size() > 0)
				{
					Parser.list_parsers.get(parser_index++).parse(line);
					
					if(parser_index % Parser.list_parsers.size() == 0)
						parser_index = 0;
					
					if(num_lines %1000 == 0)
						driver.sp(".");
				}
				
								
				++num_lines;
			}
			
			driver.directive("Import complete! Num lines read [" + num_lines + "] on file --> " + fle.getCanonicalPath());
			try	{	brIn.close();	}	catch(Exception e){}
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "import_file", e);
		}
		
		return false;
	
	}
	
	
	public String getTime_Current_hyphenated_with_seconds()
	{
		try
		{						
			return dateFormat.format(LocalDateTime.now());
		}
		catch(Exception e)
		{
			driver.sop("Invalid date specified - -" + " it does not a proper date was selected");
			//Drivers.eop("Drivers", "getTime_Specified_Millis", "", e, false);
		}
		
		
		return ""+ System.currentTimeMillis();
	}
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
}
