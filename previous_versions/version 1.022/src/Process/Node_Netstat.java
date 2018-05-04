/**
 * @author Solomon Sonya
 */

package Process;

import Driver.*;
import GEO_Location.GEO_Location;
import Map.Node_Map_Details;
import Profile.SOURCE;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.*;


public class Node_Netstat extends Thread implements Runnable, ActionListener
{
	public static volatile Driver driver = new Driver();
	public static final String myClassName = "Node_Netstat";
	
	public volatile GEO_Location geo = null;
	
	public static Process_Solomon process_netstat = new Process_Solomon(Process_Solomon.execution_action_NETSTAT);

	public static volatile boolean update_required = false;
	
	public static volatile long current_time = System.currentTimeMillis();
	
	public volatile Node_Map_Details node_map_details = null;
	public volatile String value_map = "";
	
	public static final String delimiter = "\t ";
	
	public volatile String 	PID = "",
							protocol = "",
							local_address_full = "",
							local_address = "",
							local_port = " ",
							foreign_address_full = "",
							foreign_address = "",
							foreign_port = " ",
							connection_state = "";
	

	public volatile Node_Process node_process = null;
	
	public volatile String parent_process_name = "";
	
	/**local_address_full - connection_state - foreign_address_full - PID will be the unique key for each entry*/
	public static volatile TreeMap<String, Node_Netstat> tree_netstat = new TreeMap<String, Node_Netstat>();
	
	/**Organize for unique local addresses i.e. group multiple netstat (and process entities) together based on the same local address e.g. 192.168.0.1:1234, 192.168.0.1:552, etc... all 192.168.0.1 will be under this key entry*/
	public static volatile TreeMap<String, LinkedList<Node_Netstat>> tree_grouped_local_address_netstat_entries = new TreeMap<String, LinkedList<Node_Netstat>>();
	
	/**Organize for unique foreign addresses i.e. group multiple netstat (and process entities) together based on the same foreign address e.g. 172.217.12.46:1234,172.217.12.46:9965, etc... all 172.217.12.46 will be under this key entry*/
	public static volatile TreeMap<String, LinkedList<Node_Netstat>> tree_grouped_foreign_address_netstat_entries = new TreeMap<String, LinkedList<Node_Netstat>>();
	
	public volatile long first_detection_time = System.currentTimeMillis();
	public volatile long last_detection_time = System.currentTimeMillis();
	
	public volatile String last_detection_time_text = driver.getTime_Specified_Hyphenated_with_seconds();
	public volatile String first_detection_time_text = driver.getTime_Specified_Hyphenated_with_seconds();
	
	public static volatile boolean NETSTAT_ORBITER_ENABLED = false;
	private volatile boolean process_interrupt = true;
	public volatile javax.swing.Timer tmr_interrupt = null;
	public volatile int interrupt_millis = 1000;
	
	public volatile String str = "";
	
	public volatile String [] array = new String[14];
	
	public Node_Netstat(int interrpt_millis)
	{
		try
		{	
			interrupt_millis = interrpt_millis;			
			this.start();
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "Constructor - interrupt_millis", e);
		}
	}
	
	public Node_Netstat(String pid, String proto, String local_addr_full, String foreign_addr_full, String conn_state)
	{
		try
		{
			PID = pid;
			protocol = proto;
			local_address_full = local_addr_full;
			local_address = local_addr_full;//backup
			foreign_address_full = foreign_addr_full;
			foreign_address = foreign_addr_full;//backup
			connection_state = conn_state;
			
			//
			//parse data
			//
			
			//split address from port
			if(local_address_full != null && local_address_full.contains(":"))
			{
				local_address 	= local_address_full.substring(0, local_address_full.lastIndexOf(":"));
				local_port 		= local_address_full.substring(local_address_full.lastIndexOf(":")+1);
				
				if(local_address_full.equalsIgnoreCase("*:*"))
				{
					local_address = "*:*";
					local_port = " ";
				}
			}
			
			if(foreign_address_full != null && foreign_address_full.contains(":"))
			{
				foreign_address = foreign_address_full.substring(0, foreign_address_full.lastIndexOf(":"));
				foreign_port 	= foreign_address_full.substring(foreign_address_full.lastIndexOf(":")+1);
				
				if(foreign_address_full.equalsIgnoreCase("*:*"))
				{
					foreign_address = "*:*";
					foreign_port = " ";
				}
			}
			
			//
			//set parent			
			//
			set_parent_process();
			
			
			//
			//link to unique netstat nodes!
			//
			try
			{
				//String key = local_address_full + "_" + connection_state + "_" + foreign_address_full + "_" + PID;
				String key = local_address_full + "_" + foreign_address_full + "_" + PID;
				
				if(!tree_netstat.containsKey(key))
				{
					tree_netstat.put(key,  this);
					
					driver.sop(get_new_entry_notification());
					
					update_required = true;
				}
				else
				{
					try	
					{	
						tree_netstat.get(key).connection_state = conn_state;	
						tree_netstat.get(key).last_detection_time = System.currentTimeMillis();
						
					}	catch(Exception e){}
				}
			}
			catch(Exception ee){}
									
			//
			//link to tree
			//
			if(tree_grouped_local_address_netstat_entries.containsKey(local_address))
				tree_grouped_local_address_netstat_entries.get(local_address).add(this);
			else
			{
				tree_grouped_local_address_netstat_entries.put(local_address, new LinkedList<Node_Netstat>());
				tree_grouped_local_address_netstat_entries.get(local_address).add(this);
			}
			
			//
			//link to tree
			//
			if(tree_grouped_foreign_address_netstat_entries.containsKey(foreign_address))
				tree_grouped_foreign_address_netstat_entries.get(foreign_address).add(this);
			else
			{
				tree_grouped_foreign_address_netstat_entries.put(foreign_address, new LinkedList<Node_Netstat>());
				tree_grouped_foreign_address_netstat_entries.get(foreign_address).add(this);
			}
			
			
			
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
			tmr_interrupt = new javax.swing.Timer(interrupt_millis, this);
			tmr_interrupt.start(); 
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
			if(ae.getSource() == tmr_interrupt && this.NETSTAT_ORBITER_ENABLED)
			{
				process_interrupt();
			}
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "ae", e);
		}
	}
	
	/**
	 * only proceeds if parent process has not been set yet
	 * @return
	 */
	public boolean set_parent_process()
	{
		try
		{
			if(node_process != null)
				return true;
			
			if(!Node_Process.tree_process.containsKey(PID))
				return false;
			
			node_process = Node_Process.tree_process.get(PID);
			
			if(node_process == null)
				return false;
			
			parent_process_name = node_process.Name;
			
			//link netstat object to the process
			if(node_process.list_netstat == null)
				node_process.list_netstat = new LinkedList<Node_Netstat>();
				
			if(!node_process.list_netstat.contains(this))
				node_process.list_netstat.add(this);
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "set_parent_process", e);
		}
		
		return false;
	}
	
	public String get_new_entry_notification()
	{
		try
		{
			if(this.parent_process_name != null && !this.parent_process_name.trim().equals(""))
				return ("New netstat Entry: " + "Process: [" + parent_process_name + "] " + this.protocol + " " + this.local_address + ":" + this.local_port + " --> " + this.foreign_address + ":" + this.foreign_port + " PID: [" + this.PID + "]");
			else
				return ("New netstat Entry: " + this.protocol + " " + this.local_address + ":" + this.local_port + " --> " + this.foreign_address + ":" + this.foreign_port + " PID: [" + this.PID + "]");
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "get_new_entry_notification", e);
		}
		
		return "New netstat Entry: * * * ";
	}
	
	public boolean process_interrupt()
	{
		try		
		{
			if(!this.process_interrupt)
				return false;
			
			process_interrupt = false;
			
			//update closed netstats
			Node_Netstat.update_closed_netstats();			
			
			process_netstat.exec("for /F \"tokens=1-5 delims= \" %A in ('netstat -ano') do echo %A,%B,%C,%D,%E");
			
			
			process_interrupt = true;
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "process_interrupt", e);
		}
		
		process_interrupt = true;
		return false;
	}
	
	public static boolean update_netstat_parent()
	{
		try
		{
			if(Node_Netstat.tree_netstat == null || Node_Netstat.tree_netstat.isEmpty())
				return false;
			
			LinkedList<Node_Netstat> list = new LinkedList<Node_Netstat>(Node_Netstat.tree_netstat.values());
			
			for(Node_Netstat netstat : list)
			{
				if(netstat == null)
					continue;
				
				//
				//check to update process based on PID
				//
				if(netstat.node_process == null && Node_Process.tree_process.containsKey(netstat.PID))
				{
					Node_Process process = Node_Process.tree_process.get(netstat.PID);
					
					if(process != null)
					{
						//link the process to netstat object
						netstat.node_process = process;
						netstat.parent_process_name = process.Name;
						
						//link netstat object to the process
						if(process.list_netstat == null)
							process.list_netstat = new LinkedList<Node_Netstat>();
							
						if(!process.list_netstat.contains(netstat))
							process.list_netstat.add(netstat);
						
						driver.sop("Netstat entry [" + netstat.foreign_address + "] : " + netstat.foreign_port + " has been linked to process [" + process.PID + "] - " + process.process_name);
					}
				}
			}
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "update_netstat_parent", e);
		}
		
		return false;
	}
	
	
	
	
	public String toString()
	{
		try
		{
			if(this.node_process != null)
			{							
				return 	"protocol: " + protocol + delimiter +  
						"local_address: " + local_address + delimiter + 
						"local_port: " + local_port + delimiter +
						"foreign_address: " + foreign_address + delimiter + 
						"foreign_port: " + foreign_port + delimiter +
						"connection_state: " + connection_state + delimiter +
						"PID: " + PID + delimiter + 
						node_process.get_netstat_data(delimiter) + 
						"First Detection Time: " + this.first_detection_time_text + delimiter +
						"First Detection Time_millis: " + this.first_detection_time + delimiter + 
						"Last Detection Time: " + this.last_detection_time_text + delimiter +
						"Last Detection Time_millis: " + this.last_detection_time + delimiter; 
						
			}
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "toString", e);
		}
		
		return 	"protocol: " + protocol + delimiter +  
				"local_address: " + local_address + delimiter + 
				"local_port: " + local_port + delimiter +
				"foreign_address: " + foreign_address + delimiter + 
				"foreign_port: " + foreign_port + delimiter +
				"connection_state: " + connection_state + delimiter +
				"PID: " + PID + delimiter + 
				"First Detection Time: " + this.first_detection_time_text + delimiter +
				"First Detection Time_millis: " + this.first_detection_time + delimiter + 
				"Last Detection Time: " + this.last_detection_time_text + delimiter +
				"Last Detection Time_millis: " + this.last_detection_time; 
				
	}
	
	
	
	
	public static boolean update_closed_netstats()
	{
		try
		{
			if(Node_Netstat.tree_netstat == null || Node_Netstat.tree_netstat.isEmpty())
				return false;
			
			current_time = System.currentTimeMillis();
			
			LinkedList<Node_Netstat> list = new LinkedList<Node_Netstat>(Node_Netstat.tree_netstat.values());
			
			for(Node_Netstat node : list)
			{
				if(node == null)
					continue;
				
//				if(node.last_detection_time + 10000 > current_time)
//				{
//					node.connection_state = "CLOSED";
//				}
				
				if(node.last_detection_time + 10000 < current_time)
				{
					if(!node.connection_state.equalsIgnoreCase("closed"))
					{
						node.connection_state = "CLOSED";
						update_required = true;
					}
					
					
				}
			
			}//end for
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "update_closed_netstats", e);
		}
		
		return false;
	}
	
	
	
	
	public static File export_netstat_table(boolean print_table_header, String delimiter, boolean open_file_upon_completion)
	{
		try
		{
			if(Node_Netstat.tree_netstat== null || Node_Netstat.tree_netstat.isEmpty())
				return null;
			
			//update parent nodes first
			update_netstat_parent();
			
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
			File fle = new File(path + "netstat_table.txt");
			PrintWriter pwOut = new PrintWriter(new FileWriter(fle), true);
			
			LinkedList<Node_Netstat> list = new LinkedList<Node_Netstat>(Node_Netstat.tree_netstat.values());
			
			//
			//sort based on process name
			//
			try
			{
				Collections.sort(list, new Comparator<Node_Netstat>()
				{
					public int compare(Node_Netstat t1, Node_Netstat t2)
					{
						if(t1.node_process != null && t2.node_process != null)
							return t1.node_process.process_name.compareToIgnoreCase(t2.node_process.process_name);
						
						return 0;
					}						
					
				});
			}catch(Exception ee){}
			
			//
			//print header
			//
			if(print_table_header)
				pwOut.println("process_name" + delimiter + "PID" + delimiter + "protocol" + delimiter + "local_address" + delimiter + "local_port" + delimiter + "foreign_address" + delimiter + "foreign_port" + delimiter + "connectoin_state" + delimiter + "command_line" + delimiter + "execution_path" + delimiter + "first_detection_time" + delimiter + "first_detection_time_millis" + delimiter + "last_detection_time" + delimiter + "last_detection_time_millis");
						
			
			//
			//print data
			//
			for(Node_Netstat node : list)
			{
				if(node == null)
					continue;
				
				pwOut.println(node.getTable(delimiter));
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
			driver.eop(myClassName, "export_netstat_table", e);
		}
		
		return null;
	}
	
	
	/**
	 * 
	 * @return
	 */
	public String getTable(String delimiter)
	{
		try
		{
			if(this.node_process != null)
			{
				return 	this.node_process.process_name + delimiter + 
						this.PID  + delimiter + 
						protocol + delimiter +  
						local_address + delimiter + 
						local_port + delimiter +
						foreign_address + delimiter + 
						foreign_port + delimiter +
						connection_state + delimiter +						
						node_process.CommandLine + delimiter + 
						node_process.ExecutablePath + delimiter + 
						this.first_detection_time_text + delimiter +
						this.first_detection_time + delimiter + 
						this.last_detection_time_text + delimiter +
						this.last_detection_time + delimiter; 
				
			}
			
			//otw...
			
			return 	" " + delimiter + 
					this.PID  + delimiter + 
					protocol + delimiter +  
					local_address + delimiter + 
					local_port + delimiter +
					foreign_address + delimiter + 
					foreign_port  + delimiter +  
					" " + delimiter + 
					" " + delimiter + 
					this.first_detection_time_text + delimiter +
					this.first_detection_time + delimiter + 
					this.last_detection_time_text + delimiter +
					this.last_detection_time; 
				
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "getTable", e);
		}
		
		return this.PID + "- - - ";
	}
	
	
	public static File export_netstat_tree(boolean print_table_header, String delimiter, boolean open_file_upon_completion, TreeMap<String, LinkedList<Node_Netstat>> tree, String file_name)
	{
		try
		{
			if(tree== null || tree.isEmpty())
				return null;
			
			//update parent nodes first
			update_netstat_parent();
			
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
			
			for(String key : tree.keySet())
			{
				pwOut.println(key);
				
				LinkedList<Node_Netstat> list = tree.get(key);
				
				if(list == null || list.isEmpty())
					continue;
				
				
				//
				//print data
				//
				for(Node_Netstat node : list)
				{
					if(node == null)
						continue;
					
					pwOut.println("\t" + node.toString());
				}
				
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
			driver.eop(myClassName, "export_netstat_tree", e);
		}
		
		return null;
	}
	
	public boolean update_my_netstat_process_parent()
	{
		try
		{
			if(node_process == null && Node_Process.tree_process.containsKey(PID))
			{
				Node_Process process = Node_Process.tree_process.get(PID);
				
				if(process != null)
				{
					//link the process to netstat object
					node_process = process;
					parent_process_name = process.Name;
					
					//link netstat object to the process
					if(process.list_netstat == null)
						process.list_netstat = new LinkedList<Node_Netstat>();
						
					if(!process.list_netstat.contains(this))
						process.list_netstat.add(this);
					
					driver.sop("[*] Netstat entry [" + foreign_address + "] : " + foreign_port + " has been linked to process [" + process.PID + "] - " + process.process_name);
				}
			}
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "update_my_netstat_process_parent", e);
		}
		
		return false;
	}
	
	public String [] get_jtable_row()
	{
		try
		{						
			if(this.node_process == null)
			{
				update_my_netstat_process_parent();
			}
			
			
			if(this.node_process != null)
			{
				array[0] = this.node_process.Name;
				array[1] = this.PID;
				array[2] = this.protocol;
				array[3] = this.local_address;
				array[4] = this.local_port;
				array[5] = this.foreign_address;
				array[6] = this.foreign_port;
				array[7] = this.connection_state;
				array[8] = this.node_process.CommandLine;
				array[9] = this.node_process.ExecutablePath;
				array[10] = this.first_detection_time_text;
				array[11] = ""+this.first_detection_time;
				array[12] = this.last_detection_time_text;
				array[13] = ""+this.last_detection_time;
			}
			
			else
			{
				array[0] = " ";
				array[1] = this.PID;
				array[2] = this.protocol;
				array[3] = this.local_address;
				array[4] = this.local_port;
				array[5] = this.foreign_address;
				array[6] = this.foreign_port;
				array[7] = this.connection_state;
				array[8] = " ";
				array[9] = " ";
				array[10] = this.first_detection_time_text;
				array[11] = ""+this.first_detection_time;
				array[12] = this.last_detection_time_text;
				array[13] = ""+this.last_detection_time;
			}
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "get_jtable_row", e);
		}
		
		return array;
	}
	
	
	public Node_Map_Details get_map_node(boolean include_map_header)
	{
		try
		{
			if(this.geo == null)
			{
				if(GEO_Location.TREE_GEO_LOCATION.containsKey(this.foreign_address))
					geo = GEO_Location.TREE_GEO_LOCATION.get(this.foreign_address);
			}
			
			if(this.geo == null)
				return null;
			
			if(node_map_details == null)
				node_map_details = new Node_Map_Details(geo.latitude, geo.longitude, this.get_map_details(include_map_header));
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
	
	
	public String get_map_details(boolean include_map_header)
	{
		try
		{
			if(this.geo == null)
			{
				if(GEO_Location.TREE_GEO_LOCATION.containsKey(this.foreign_address))
					geo = GEO_Location.TREE_GEO_LOCATION.get(this.foreign_address);
			}
			
			if(this.geo == null)
				return "";			
			
			value_map = "";
			
			if(include_map_header)
			{
				value_map = "var location = {lat:\"" + this.geo.latitude + "\", lng:\"" + this.geo.longitude +"\"}; ";
				
				
				if(SOURCE.SANITIZE_MAC)
				{								
					value_map = value_map + "var device = {ID: 'Device Classification: [" + "Requested Resource" + "]', data: '" ; 
							//+ "<br><b>MAC:</b> " + this.mac_sanitized;
				}
				else
				{
					value_map = value_map + "var device = {ID: 'Device Classification: [" + "Requested Resource" + "]', data: '"; 
							//+ "<br><b>MAC:</b> " + this.src_mac ;
				}
				
				value_map = value_map + "<br>";
			}
			
			if(this.node_process != null)
				value_map = value_map + "<b>" + this.node_process.Name + "</b>&nbsp&nbsp PID: [" + this.PID + "] <br><br>";
			else
				value_map = value_map + "<b>PID:</b> [" + this.PID + "] <br><br>";
						
			
			if(this.node_process != null)
			{
				if(node_process.ExecutablePath != null && !node_process.ExecutablePath.trim().equals(""))
					value_map = value_map + "<b>Execution Path:</b> &nbsp" + node_process.ExecutablePath + "<br><br>";
				else if(node_process.CommandLine != null && !node_process.CommandLine.trim().equals(""))
					value_map = value_map + "<b>Command Line:</b> &nbsp" + node_process.CommandLine + "<br><br>";
			}
			
			value_map = value_map + "<b>First Contact Time:</b> &nbsp" + this.first_detection_time_text + "<br>";
			value_map = value_map + "<b>Last  Contact Time:</b> &nbsp" + this.last_detection_time_text + "<br>";
			value_map = value_map + "<br>";			
			
			
			//GEO
			if(geo != null)
				value_map = value_map + geo.get_map_details();	
			
			value_map = value_map + "<br>";
							
			
			if(include_map_header)
			{
				//terminate
				value_map = value_map + "'};	plotMarker(map, location, device);";
			}
					 			 			 															
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "get_map_details", e);
		}
		
		return value_map;
	}
	
	
	
	
	
	
	
	
	
	
	
}
