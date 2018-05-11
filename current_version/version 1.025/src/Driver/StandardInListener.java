/**
 * @author Solomon Sonya
 */

package Driver;

import Process.*;
import java.awt.BorderLayout;
import java.io.*;
import java.net.Socket;
import java.util.LinkedList;
import java.util.TreeMap;
import java.util.*;
import nmap.*;
import Interface.*;
import Map.GoogleMap;
import Map.Node_Map_Details;

import javax.swing.*;
import Interface.*;
import Encryption.Encryption;
import GEO_Location.GEO_Location;
import Parser.*;
import Cookie.*;
import Profile.Resolution;
import Profile.SOURCE;
import ResolutionRequest.ResolutionRequest_ServerSocket;
import ResolutionRequest.ResolutionRequest_ThdSocket;
import Sensor.*;
import Typed_URL.Node_URL;
import Worker.ThdWorker;

public class StandardInListener extends Thread implements Runnable
{
	public volatile static Driver driver = new Driver();
	public static final String myClassName = "StandardInListener";
	public static volatile Resolution resolution_search = null;
	public static volatile Application application_search = null;
	
	public static volatile String lower = "";
	
	public volatile PrintWriter pwOut = null;
	public volatile BufferedReader brIn = null;
	
	public static volatile TreeMap<String, Integer> tmp_packet_count = new TreeMap<String, Integer>();	
	public static volatile TreeMap<String, Integer> tmp_packet_count_OVERFLOW = new TreeMap<String, Integer>();
	
	public static volatile boolean launch_configuration_BOTH_SENSOR_AND_PARSER = false;
	public static volatile boolean launch_configuration_PARSER = false;
	public static volatile boolean launch_configuration_SENSOR = false;
	
	public static volatile TreeMap<String, Integer> tmp_packet_count_total = new TreeMap<String, Integer>();	
	public static volatile TreeMap<String, Integer> tmp_packet_count_OVERFLOW_bar = new TreeMap<String, Integer>();
	public static volatile int max_overflow_count = 0;
	
	public static volatile int count = 0;
	
	public static volatile boolean stop = false;
	public static Interface intrface = null;
	
	public static volatile LinkedList<String> vctColHeaders = new LinkedList<String>();
	public static volatile String [] colHeaders = null;
	
	public static volatile int parser_index = 0;
	public static volatile int i = 0, j = 0, k = 0, l = 0;;
	public static volatile String [] packet_names = null;
	public static volatile int [] packet_values = null;
	
	public static volatile String selected_row_id = "";
	public static volatile SOURCE selected_node_to_monitor = null;
	public static volatile String [] arrNames_selected_node_to_monitor = null;
	public static volatile int [] arrValues_selected_node_to_monitor = null;
	
	public static volatile LinkedList<Resolution> list_unique_resolution_EXTERNAL = new LinkedList<Resolution>();
	public static volatile LinkedList<Resolution> list_unique_resolution_INTERNAL = new LinkedList<Resolution>();
	public static volatile String [] arrNames_resource_external = null;
	public static volatile int [] arrValues_resource_external = null;
	public static volatile String [] arrNames_resource_internal = null;
	public static volatile int [] arrValues_resource_internal = null;
	
	public static volatile String [] arrJTblCookie = null;
	public static volatile String [] arrCookie = null;
	public static volatile Resolution resolution_cookie = null;
	public static volatile String cookie = "", full_uri_cookie = "", domain_name_cookie = "";
	
	public static volatile LinkedList<File> list_cookies_host_system_files = new LinkedList<File>();
	
	public static volatile LinkedList<Node_Map_Details> list_map_details = new LinkedList<Node_Map_Details>();
	public static volatile LinkedList<Node_Map_Details> list_map_details_process = new LinkedList<Node_Map_Details>();
	
	
	public StandardInListener()
	{
		try
		{
			brIn = new BufferedReader(new InputStreamReader(System.in));
			pwOut = new PrintWriter(new BufferedOutputStream(System.out));
			
			
			
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
			String line = "";
			
			while((line = brIn.readLine())!= null) 
			{
				line = line.trim();
				
				if(line.equals(""))
					continue;
				
				determineCommand(line);
			}
			
			driver.directive("\n\nBreaking from Infinite Loop in " + myClassName + ". Ready to terminate program!");
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "run", e);
		}
	}
	
	public boolean determineCommand(String line)
	{
		try
		{
			if(line == null || line.trim().equals(""))
				return false;
			
			line = line.trim();
			
			lower = line.toLowerCase().trim();
			
			if(line.equalsIgnoreCase("status") || line.equalsIgnoreCase("s") || line.equalsIgnoreCase("-status") || line.equalsIgnoreCase("-s") || (line.contains("display") && line.contains("status")))
				display_status();
			
			else if(lower.startsWith("import_geo") || lower.startsWith("import geo") || lower.startsWith("import_gps") || lower.startsWith("import gps"))
			{
				GEO_Location geo = new GEO_Location(true, null);
			}
			
			else if(lower.startsWith("restart_sensor") || lower.startsWith("restart sensor"))
				restart_sensor();
			
			else if(lower.startsWith("draw_map") || lower.startsWith("draw map"))
				ThdWorker.draw_maps();
			
			else if(lower.startsWith("map_source") || lower.startsWith("map source") || lower.startsWith("map_src") || lower.startsWith("map src"))
				map_source_nodes();
			
			else if(lower.startsWith("map_resource") || lower.startsWith("map resource") || lower.startsWith("map_rsrc") || lower.startsWith("map rsrc") || lower.startsWith("map_resolution") || lower.startsWith("map resolution") || lower.startsWith("map_rsltn") || lower.startsWith("map rstln"))
				map_resolution_nodes();
			
			else if(lower.startsWith("map_connection") || lower.startsWith("map connection") || lower.startsWith("map_marker") || lower.startsWith("map marker"))
				map_connection_markers();
			
			else if(lower.startsWith("map_process") || lower.startsWith("map process"))
				map_process();
			
			else if(line.equalsIgnoreCase("verbose") || line.equalsIgnoreCase("v") || line.equalsIgnoreCase("-verbose") || line.equalsIgnoreCase("-v"))
				toggle_verbose();	
			
			else if(lower.startsWith("export_cookies") || lower.startsWith("export cookie"))
				Cookie_Container_Host_System.export_cookies(true, "\t");
			
			else if(lower.startsWith("export_geo") || lower.startsWith("export geo"))
				GEO_Location.export_geo(true,  "\t",  true,  "geo_table.txt");
			
			else if(lower.startsWith("export_netstat") || lower.startsWith("export netstat"))
				export_netstat();
			
			else if(lower.startsWith("export_process") || lower.startsWith("export process") || lower.startsWith("export_tasklist") || lower.startsWith("export tasklist"))
				export_process();
			
			else if(lower.startsWith("export_url") || lower.startsWith("export url") || lower.startsWith("export_typed_url") || lower.startsWith("export typed url"))
				export_typed_url();
			
			else if(line.equalsIgnoreCase("update_geo") || line.equalsIgnoreCase("update geo") || line.equalsIgnoreCase("update gps") || line.equalsIgnoreCase("update gps"))
				update_geo();
			
			else if(line.toLowerCase().startsWith("import"))
				import_file(null);
			
			else if(line.toLowerCase().startsWith("nmap enable") || line.toLowerCase().startsWith("nmap_enable") || line.toLowerCase().startsWith("enable nmap") || line.toLowerCase().startsWith("enable_nmap") )
				set_nmap_enabled(true);
			
			else if(line.toLowerCase().startsWith("nmap disable") || line.toLowerCase().startsWith("nmap_disable") || line.toLowerCase().startsWith("disable nmap") || line.toLowerCase().startsWith("disable_nmap") )
				set_nmap_enabled(false);
			
			else if(line.toLowerCase().startsWith("parser_connect") || line.toLowerCase().startsWith("parser connect"))
				parser_connect(line.substring(14));
			
			else if(line.toLowerCase().startsWith("sensor_connect") || line.toLowerCase().startsWith("sensor connect"))
				sensor_connect(line.substring(14));
			
			else if(line.toLowerCase().startsWith("resolution_connect") || line.toLowerCase().startsWith("resolution connect"))
				resolution_connect(line.substring(18));
			
			else if(line.toLowerCase().startsWith("resolution_request") || line.toLowerCase().startsWith("resolution request"))
				resolution_connect(line.substring(18));
			
			else if(line.toLowerCase().startsWith("request_resolution") || line.toLowerCase().startsWith("request resolution"))
				resolution_connect(line.substring(18));
			
			else if(line.toLowerCase().startsWith("request_connect") || line.toLowerCase().startsWith("request connect"))
				resolution_connect(line.substring(15));
			
			else if(line.toLowerCase().startsWith("listen"))
				establish_server_socket(line.substring(6));
			
			else if(line.toLowerCase().startsWith("-listen"))
				establish_server_socket(line.substring(7));
			
			else if(line.toLowerCase().startsWith("-establish_server_socket"))
				establish_server_socket(line.substring(24));
			
			else if(line.toLowerCase().startsWith("establish_server_socket"))
				establish_server_socket(line.substring(23));
			
			else if(line.toLowerCase().startsWith("-establish server socket"))
				establish_server_socket(line.substring(24));
			
			else if(line.toLowerCase().startsWith("establish server socket"))
				establish_server_socket(line.substring(23));
			
			else if(line.toLowerCase().startsWith("verbose_sensor") || line.toLowerCase().startsWith("verbose sensor") || line.toLowerCase().startsWith("sensor_verbose") || line.toLowerCase().startsWith("sensor verbose") )
				toggle_verbose_sensor();
			
			else if(line.toLowerCase().startsWith("verbose_parser") || line.toLowerCase().startsWith("verbose parser") || line.toLowerCase().startsWith("parser_verbose") || line.toLowerCase().startsWith("parser verbose") )
				toggle_verbose_parser();
			
			else if(line.toLowerCase().startsWith("-set_encryption") || line.toLowerCase().startsWith("-set encryption"))
				set_encryption(line.substring(15));
			
			else if(line.toLowerCase().startsWith("set_encryption") || line.toLowerCase().startsWith("set encryption"))
				set_encryption(line.substring(14));
			
			else if(line.toLowerCase().startsWith("encryption"))
				set_encryption(line.substring(10));
			
			else if(line.toLowerCase().startsWith("process"))
				process_line(line.substring(7));
			
			else if(line.toLowerCase().equalsIgnoreCase("log"))
				toggle_logging();
			
			else if(line.equalsIgnoreCase("disconnect"))
				disconnect_all();
			
			else if(line.equalsIgnoreCase("interface"))
			{
				if(intrface == null)
					intrface = new Interface();
				else
					driver.directive("PUNT! Interface is already instantiated!");
			}
			
			
			
			else if(line.equalsIgnoreCase("protocol_index") || line.equalsIgnoreCase("protocol index"))
				print_protocol_index();
			
			else if(line.equalsIgnoreCase("protocol") || line.equalsIgnoreCase("print_protocol") || line.equalsIgnoreCase("print protocol"))
				print_protocol_summary("\t");
			
			else if(line.equalsIgnoreCase("write_protocol") || line.equalsIgnoreCase("write protocol"))
				this.write_protocol_summary("\t");
			
			else if(line.equalsIgnoreCase("stop"))
				stop = true;
			
			else if(line.toLowerCase().equals("exit"))
			{
				exit();
			}
			
			
			else if(line.equals("w"))
			{
				sensor_connect("localhost 3000");
				resolution_connect("localhost 1000");				
			}
			
			else if(line.equals("w1"))
			{
				if(intrface == null)
					intrface = new Interface();
				
				sensor_connect("192.168.0.106 9998");
				//sensor_connect("localhost 3000");
				//resolution_connect("localhost 1000");
				
				
			}
			
			else if(line.equals("w2"))
			{
				sensor_connect("localhost 1000");
				resolution_connect("localhost 3000");				
			}
			
			else
			{
				driver.directive("unrecognized command --> " + line);		
			}
				
		
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "determineCommand", e);
		}
		
		return false;
	}
	
	public static boolean restart_sensor()
	{
		try
		{
			if(Sensor.tree_EXECUTING_SENSOR_COMMAND == null || Sensor.tree_EXECUTING_SENSOR_COMMAND.isEmpty())
			{
				driver.directive("Punt! No sensor commands have been cached in the system yet!");
				return false;
			}
			
			for(Tuple tuple : Sensor.tree_EXECUTING_SENSOR_COMMAND.values())
			{
				if(tuple == null)
					continue;
				
				Sensor sensor = new Sensor(tuple.value_1, tuple.value_2);
			}
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "restart_sensor", e);
		}
		
		return false;
	}
	
	public static boolean export_netstat()
	{
		try
		{
			if((Node_Netstat.tree_netstat == null || Node_Netstat.tree_netstat.isEmpty() ) && (Node_Process.tree_process == null  || Node_Process.tree_process.isEmpty()))
			{
				driver.directive("Punt! No values are available to export at this time!");
				return false;
			}
			
			Node_Process.export_process_tree();
			Node_Netstat.export_netstat_tree(false, "\t", true, Node_Netstat.tree_grouped_foreign_address_netstat_entries, "netstat_foreign_address_tree.txt");
			Node_Netstat.export_netstat_tree(false, "\t", true, Node_Netstat.tree_grouped_local_address_netstat_entries, "netstat_local_address_tree.txt");
			
			Node_Netstat.export_netstat_table(true, "\t", true);
			Node_Process.export_process_table(true,  "\t",  true);
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "export_netstat", e);
		}
		
		return false;
	}
	
	public static File export_typed_url()
	{
		try
		{
			return Node_URL.export_typed_url("\t", true);
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "export_typed_url", e);
		}
		
		return null;
	}
	
	public static boolean export_process()
	{
		try
		{
			//for now, just use the same process...
			
			return export_netstat();
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "export_process", e);
		}
		
		return false;
	}
	
	public static boolean update_geo()
	{
		try
		{
			driver.directive("Updating applicable geo entries...");
			GEO_Location.update_geo_resolution();
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "update_geo", e);
		}
		
		return false;
	}
	
	public static boolean set_nmap_enabled(boolean enabled)
	{
		try
		{
			NMap.NMAP_ENABLED = enabled;
			
			if(NMap.NMAP_ENABLED)
			{
				driver.directive("NMAP is enabled");
				
				//check if necessary to configure nmap
				if(NMap.fleNmap == null || !NMap.fleNmap.exists() || !NMap.fleNmap.isFile())
					Start.configure_nmap();
				
				//if still no good, then set disabled
				if(NMap.fleNmap == null || !NMap.fleNmap.exists() || !NMap.fleNmap.isFile())
					return set_nmap_enabled(false);
			}
			else
			{
				driver.directive("NMAP is disabled");
				
				if(intrface.jtblNetworkMap != null && intrface.jrbNetworkMapDisabled != null)
					intrface.jrbNetworkMapDisabled.setSelected(true);
			}
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "set_nmap_enabled", e);
		}
		
		return false;
	}
	
	public static boolean process_line(String line)
	{
		try
		{
			if(line == null || line.trim().equals(""))
				return false;
			
			if(Parser.list_parsers == null || Parser.list_parsers.size() < 1)
			{
				driver.directive("NOTE! You have not started Parsers yet! I will start them for you...");
				Start.configure_parser(false);
			}
			
			//do not trim!
			
			if(Parser.list_parsers != null && Parser.list_parsers.size() > 0)
			{
				Parser.list_parsers.get(parser_index++).parse(line);
				
				if(parser_index % Parser.list_parsers.size() == 0)
					parser_index = 0;
			}
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "process_line", e);
		}
		
		return false;
	}
	
	public static boolean import_file(File fle)
	{
		try
		{
			if(fle == null || !fle.exists() || !fle.isFile())
				fle = driver.querySelectFile(true, "Please select file to import", JFileChooser.FILES_ONLY, false, false);
			
			if(fle == null || !fle.exists() || !fle.isFile())
			{
				driver.directive("\nPUNT! No valid file selected!");
				return false;
			}
			
			ImportFile import_file = new ImportFile(fle);
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "import_file", e);
		}
		
		return false;
	}
	
	public boolean print_protocol_index()
	{
		try
		{
			if(SOURCE.tree_protocol_header_names == null || SOURCE.tree_protocol_header_names.isEmpty())
			{
				driver.directive("PUNT! No protocols have been processed yet...");
				return false;
			}
			
			for(String protocol : SOURCE.tree_protocol_header_names.values())
			{
				driver.directive(protocol);
			}
									
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "print_protocol_index", e);
		}
		
		return false;
	}
	
	public boolean print_protocol_summary(String delimiter)
	{
		try
		{
			if(SOURCE.tree_protocol_header_names == null || SOURCE.tree_protocol_header_names.isEmpty())
			{
				driver.directive("PUNT! No protocols have been processed yet...");
				return false;
			}
			
			if(SOURCE.TREE_SOURCE_NODES == null || SOURCE.TREE_SOURCE_NODES.isEmpty())
			{
				driver.directive("PUNT! No nodes have been processed yet...");
				return false;
			}
			
			driver.directive("Printing Protocol Summary ");
			
			//write header
			String header = "SOURCE " + delimiter + "MAC " + delimiter + "FIRST_CONTACT" + delimiter + "LAST_CONTACT" + delimiter;
			
			for(String hdr : SOURCE.tree_protocol_header_names.values())
				header = header + hdr + delimiter;
			
			driver.directive(header);
			
			//check if updating interface
			initialize_interface_jtbl(true);
			
			//write totals
			driver.directive(get_packet_count_summary(delimiter, true));
			
			//print contents
			for(SOURCE node : SOURCE.TREE_SOURCE_NODES.values())
			{
				if(node == null)
					continue;
				
				driver.directive(node.get_protocol_summary("\t", true));
				
				//update to interface
				if(intrface != null && intrface.jtblSourceNodes != null)
				{
					intrface.jtblSourceNodes.addRow(node.get_jtable_row_summary("\t", false));
				}
			}
			
			resort_interface_jtblProtocol();
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "print_protocol_summary", e);
		}
		
		return false;
	}
	
	public static boolean resort_interface_jtblProtocol()
	{
		try
		{
			//done, resort interface if needed
			//update to interface
			if(intrface != null && intrface.jtblSourceNodes != null)
			{
				intrface.jtblSourceNodes.sortJTable_ByRows(intrface.jtblSourceNodes.dfltTblMdl, intrface.jtblSourceNodes.jcbSortTableBy.getSelectedIndex(), intrface.jtblSourceNodes.sortInAscendingOrder);
			}
			
			return true;
		}
		
		catch(Exception e)
		{
			driver.eop(myClassName, "resort_interface_jtblProtocol", e);				
		}
		
		return false;
	}
	
	public static boolean initialize_interface_jtbl(boolean clear_previous_rows)
	{
		try
		{
			if(intrface != null)
			{
				//reject if necessary
				try
				{
					if(intrface.jtblSourceNodes.jcbRejectUpdate.isSelected())
						return true;
				}catch(Exception e){}
				
				//check if we need to initialize jtable
				if(intrface.jtblSourceNodes == null || intrface.jtblSourceNodes.vctColNames == null || intrface.jtblSourceNodes.vctColNames.size() != (SOURCE.tree_protocol_header_names.size() + 4))
				{									
					String [] colHeader = get_jtable_protocol_summary_headers();
					
					//check if we need to invalidate the previous jtable
					if(intrface.jtblSourceNodes != null)
					{
						//remove
						//if(clear_previous_rows && !intrface.jtblProtocol.jcbRejectUpdate.isSelected())
						
						//clear prev entries
						try	{	intrface.jtblSourceNodes.jtblMyJTbl.removeAll();	}	catch(Exception e){}
						try	{	intrface.jtblSourceNodes.tmrUpdateJTable.stop();	intrface.jtblSourceNodes.tmrUpdateJTable = null;}	catch(Exception e){}
						try	{	intrface.jtblSourceNodes.removeAll();	}	catch(Exception e){}
						
						
							try	{	intrface.jpnl_jtblSourceNodes.removeAll();	}	catch(Exception e)	{intrface.jpnl_jtblSourceNodes = new JPanel(new BorderLayout());}
						
						//invalidate
						intrface.jtblSourceNodes = null;
						
					}
					
					//create new jtabel
					intrface.jtblSourceNodes = new JTable_Solomon(false, colHeader, colHeader, "Source Nodes", null, null, false, 140, "", false, 4);
					
					//add new jtable
					intrface.jpnl_jtblSourceNodes.add(BorderLayout.CENTER, intrface.jtblSourceNodes);
					intrface.jpnl_jtblSourceNodes.add(BorderLayout.SOUTH, intrface.jpnlNotification_South);
					intrface.jtblSourceNodes.jpopup_SelectedRow.add(intrface.jmnuitem_MonitorInSummary);
					
					intrface.jtblSourceNodes.jpnlNotification_South.add(intrface.jbtnMapSelectedNode_Source_Node);
					
					
					intrface.jpnl_jtblSourceNodes.validate();
					intrface.jfrm.validate();
				}
				
				//clear entries
				if(clear_previous_rows && !intrface.jtblSourceNodes.jcbRejectUpdate.isSelected())
					try	{	intrface.jtblSourceNodes.removeAllRows();	}	catch(Exception e){}
								
			}
			
			System.gc();
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "initialize_interface_jtbl", e);
		}
		
		return false;
	}
	
	public static boolean resort_interface_jtblResolution()
	{
		try
		{
			//done, resort interface if needed
			//update to interface
			if(intrface != null && intrface.jtblResolution != null)
			{
				intrface.jtblResolution.sortJTable_ByRows(intrface.jtblResolution.dfltTblMdl, intrface.jtblResolution.jcbSortTableBy.getSelectedIndex(), intrface.jtblResolution.sortInAscendingOrder);
			}
			
			return true;
		}
		
		catch(Exception e)
		{
			driver.eop(myClassName, "resort_interface_jtblResolution", e);				
		}
		
		return false;
	}
	
	public static boolean resort_interface_jtblApplication()
	{
		try
		{
			//done, resort interface if needed
			//update to interface
			if(intrface != null && intrface.jtblApplicationCategorization_out != null)
			{
				intrface.jtblApplicationCategorization_out.sortJTable_ByRows(intrface.jtblApplicationCategorization_out.dfltTblMdl, intrface.jtblApplicationCategorization_out.jcbSortTableBy.getSelectedIndex(), intrface.jtblApplicationCategorization_out.sortInAscendingOrder);
			}
			
			return true;
		}
		
		catch(Exception e)
		{
			driver.eop(myClassName, "resort_interface_jtblApplication", e);				
		}
		
		return false;
	}
	
	public static boolean resort_interface_jtblCookies_NetworkCapture()
	{
		try
		{
			//done, resort interface if needed
			//update to interface
			if(intrface != null && intrface.jtblCookies_NetworkCapture != null)
			{
				intrface.jtblCookies_NetworkCapture.sortJTable_ByRows(intrface.jtblCookies_NetworkCapture.dfltTblMdl, intrface.jtblCookies_NetworkCapture.jcbSortTableBy.getSelectedIndex(), intrface.jtblCookies_NetworkCapture.sortInAscendingOrder);
			}
			
			return true;
		}
		
		catch(Exception e)
		{
			driver.eop(myClassName, "resort_interface_jtblCookies", e);				
		}
		
		return false;
	}
	
	public static boolean update_jtbl_Nodes(boolean re_init_entire_table)
	{
		try
		{
			if(intrface == null)
				return false;
			
			if(SOURCE.TREE_SOURCE_NODES == null || SOURCE.TREE_SOURCE_NODES.isEmpty())
				return false;
			
			if(intrface.jlblNodesCount == null)
				return false;
			
			if(intrface.jtblSourceNodes == null)
				return false;
			
			
			try	{	intrface.jlblNodesCount.setText("Nodes: " + SOURCE.TREE_SOURCE_NODES.size());} catch(Exception e){}
			
			if(intrface.jtblSourceNodes.jcbRejectUpdate.isSelected())
				return true;
			
			
			
			if(re_init_entire_table)
				initialize_interface_jtbl(re_init_entire_table);
			
			//print contents
			for(SOURCE node : SOURCE.TREE_SOURCE_NODES.values())
			{
				if(node == null)
					continue;
												
				//update to interface
				if(intrface != null && intrface.jtblSourceNodes != null)
				{
					intrface.jtblSourceNodes.addRow(node.get_jtable_row_summary("\t", false));
				}
			}
			
			//sort
			resort_interface_jtblProtocol();
			
			return true;
		}
		catch(ConcurrentModificationException cme)
		{
			driver.directive("Hold fast, I am currently modifying source node trees...");
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "update_jtbl_Nodes", e);
		}
		
		return false;
		
	}
	
	public static String [] get_jtable_protocol_summary_headers()
	{
		try
		{
			int overhead = 4;
			
			try	{	vctColHeaders.clear();}	catch(Exception e){vctColHeaders = new LinkedList<String>();		}
			
			vctColHeaders.add("SOURCE");
			vctColHeaders.add("MAC");
			vctColHeaders.add("DEVICE IDENTIFIER (OUI)");
			vctColHeaders.add("DOMAIN NAME REQUESTS");
			vctColHeaders.add("RESOURCES");
			vctColHeaders.add("COOKIES");
			vctColHeaders.add("HTTP HOSTS");
			vctColHeaders.add("HTTP REFERERS");
			
			vctColHeaders.add("ALERT");
			vctColHeaders.add("FIRST_CONTACT");
			vctColHeaders.add("LAST_CONTACT");
			vctColHeaders.add("PRIVATE ADDRESS");
					
			for(String col :  SOURCE.tree_protocol_header_names.values())
			{
				if(col == null)
					col = "-";
				
				col = col.trim();
				
				vctColHeaders.add(col);
			}
			
			colHeaders = new String[vctColHeaders.size()];
			
			for(int i = 0; i < colHeaders.length; i++)
			{
				colHeaders[i] = vctColHeaders.get(i);
			}
			
			return colHeaders;
						
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "get_jtable_protocol_summary_headers", e);
		}
		
		return null;
	}
	
	public static boolean update_network_statistics_array_name_and_values_()
	{
		//write totals
		try
		{						
			tmp_packet_count_total.clear();
			tmp_packet_count_OVERFLOW_bar.clear();
			
			if(SOURCE.tree_protocol_header_names == null || SOURCE.tree_protocol_header_names.isEmpty())
			{
				return false;
			}
			
			//iterate through and populate the list first			
			
			for(String hdr : SOURCE.tree_protocol_header_names.values())
			{		
				try
				{
					count = 0;
					
					for(SOURCE node : SOURCE.TREE_SOURCE_NODES.values())
					{
						if(count >= (Integer.MAX_VALUE-9999))
						{
							tmp_packet_count_total.put(hdr, 0);
							tmp_packet_count_OVERFLOW_bar.put(hdr, (tmp_packet_count_OVERFLOW.get(hdr)+1));

							if(tmp_packet_count_OVERFLOW_bar.get(hdr) > max_overflow_count)
								max_overflow_count = tmp_packet_count_OVERFLOW_bar.get(hdr);
						}
						
						if(!node.tree_packet_count.containsKey(hdr))
							continue;
						
						//otw
						count += node.tree_packet_count.get(hdr);
						tmp_packet_count_total.put(hdr, count);
					}										
				}
				
				catch(Exception e)
				{
					continue;
				}
			}
			
			
			
			//finally, put the string together!
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "update_network_statistics_array_name_and_values_", e);
		}
		
		return false;
	}
	
	public static boolean update_BAR_overall_network_statistics()
	{
		try
		{
			if(intrface == null)
				return false;
			
			if(SOURCE.tree_protocol_header_names == null || SOURCE.tree_protocol_header_names.isEmpty())
			{
				driver.jop_Error("No protocol values have been loaded yet...");
				return false;
			}
						
			//first update array and values
			update_network_statistics_array_name_and_values_();
			
			//instantiate the arrays
			packet_names = new String[tmp_packet_count_total.size()];
			packet_values = new int[tmp_packet_count_total.size()];
									
			i = 0;
			for(String header : tmp_packet_count_total.keySet())
			{
				
				
				if(header == null)
					continue;
				
				packet_names[i] = header;
				
				if(max_overflow_count > 1)
					packet_values[i] = (int)Math.ceil(tmp_packet_count_total.get(header)/max_overflow_count);
				else
					packet_values[i] = tmp_packet_count_total.get(header);
				
				++i;
			}
									
			//display values
			intrface.bar_network_statistics.display_data(packet_names, packet_values);
			
			System.gc();
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "update_BAR_overall_network_statistics", e);
		}
		
		return false;
	}
	
	public static boolean update_jtbl_resolution(boolean re_init_entire_table)
	{
		try
		{
			if(intrface == null)
				return false;
			
			if(intrface.jtblResolution == null)
				return false;
			
			if(Resolution.TREE_RESOURCE == null || Resolution.TREE_RESOURCE.isEmpty())
				return false;
			
			try	{	intrface.jlblResourcesCount.setText("Resources: " + Resolution.TREE_RESOURCE.size());} catch(Exception e){}
			
			
			if(intrface.jtblResolution.jcbRejectUpdate.isSelected())
				return true;
			
			
			//
			//CLEAR
			//
			intrface.jtblResolution.removeAllRows();
			
			/*//
			//UNRESOLUVED LIST
			//
			for(Resolution resolution : Resolution.tree_unresolved_request.values())
			{
				if(resolution == null)
					continue;
												
				//update to interface
				if(intrface != null && intrface.jtblResolution != null)
				{
					intrface.jtblResolution.addRow(resolution.get_jtable_row_summary("\t", false));
				}
			}

			//
			//RESOLVED LIST
			//
			for(Resolution resolution : Resolution.tree_resolution.values())
			{
				if(resolution == null)
					continue;
												
				//update to interface
				if(intrface != null && intrface.jtblResolution != null)
				{
					intrface.jtblResolution.addRow(resolution.get_jtable_row_summary("\t", false));
				}
			}*/
			
			//
			//RESOLVED LIST
			//			
			for(String key : Resolution.TREE_RESOURCE.keySet())
			{
				if(key == null || key.trim().equals(""))
					continue;
				
				resolution_search = Resolution.TREE_RESOURCE.get(key);
				
				if(resolution_search == null)
					continue;												
				
				intrface.jtblResolution.addRow(key, resolution_search.get_jtable_row_summary("\t", false));				
			}
			
						
			//sort
			resort_interface_jtblResolution();
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "update_jtbl_protocol", e);
		}
		
		return false;
		
	}
	
	public static boolean update_PIE_overall_network_statistics(boolean update_corresponding_bar_chart)
	{
		try
		{
			if(intrface == null)
				return false;
			
			if(SOURCE.tree_protocol_header_names == null || SOURCE.tree_protocol_header_names.isEmpty())
			{
				driver.jop_Error("Punt! No protocol values have been loaded yet...");
				return false;
			}
						
			//first update array and values
			update_network_statistics_array_name_and_values_();
			
			//instantiate the arrays
			packet_names = new String[tmp_packet_count_total.size()];
			packet_values = new int[tmp_packet_count_total.size()];
						
			
			j = 0;
			for(String header : tmp_packet_count_total.keySet())
			{								
				if(header == null)
					continue;
				
				packet_names[j] = header;
				
				if(max_overflow_count > 1)
					packet_values[j] = (int)Math.ceil(tmp_packet_count_total.get(header)/max_overflow_count);
				else
					packet_values[j] = tmp_packet_count_total.get(header);
				
				++j;
			}
			
						
			intrface.pie_network_statistics.display_data(packet_names, packet_values, update_corresponding_bar_chart);
			
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "update_PIE_overall_network_statistics", e);
		}
		
		return false;
	}
	
	public static boolean update_jtbl_application(boolean re_init_entire_table)
	{
		try
		{
			if(intrface == null)
				return false;
			
			if(intrface.jtblApplicationCategorization_out == null)
				return false;
			
			if(Application.TREE_APPLICATION == null || Application.TREE_APPLICATION.isEmpty())
				return false;
						
			
			if(intrface.jtblApplicationCategorization_out.jcbRejectUpdate.isSelected())
				return true;
			
			
			//
			//CLEAR
			//
			intrface.jtblApplicationCategorization_out.removeAllRows();
			
			
			//
			//RESOLVED LIST
			//			
			for(String key : Application.TREE_APPLICATION.keySet())
			{
				if(key == null || key.trim().equals(""))
					continue;
				
				application_search = Application.TREE_APPLICATION.get(key);
				
				if(application_search == null)
					continue;												
				
				intrface.jtblApplicationCategorization_out.addRow(key, application_search.get_jtable_row_summary("\t"));				
			}
			
						
			//sort
			resort_interface_jtblApplication();
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "update_jtbl_application", e);
		}
		
		return false;
		
	}
	
	
	public static boolean update_jtbl_cookies()
	{
		try
		{
			if(intrface == null)
				return false;
			
			if(intrface.jtblCookies_NetworkCapture == null)
				return false;
			
			if(SOURCE.TREE_SOURCE_NODES == null || SOURCE.TREE_SOURCE_NODES.isEmpty())
				return false;
						
			
			if(intrface.jtblCookies_NetworkCapture.jcbRejectUpdate.isSelected())
				return true;
			
			
			//
			//CLEAR
			//
			intrface.jtblCookies_NetworkCapture.removeAllRows();
			
			
			//
			//RESOLVED LIST
			//			
			for(SOURCE node : SOURCE.TREE_SOURCE_NODES.values())
			{
				if(node == null)
					continue;
				
				if(node.tree_my_cookie == null || node.tree_my_cookie.isEmpty())
					continue;
				
				for(String key : node.tree_my_cookie.keySet())
				{
					if(key == null || key.trim().equals(""))
						continue;
					
					resolution_cookie = node.tree_my_cookie.get(key);
					
					//bifurcate cookie from full uri
					/*arrCookie = key.split(",");
					
					if(arrCookie == null || arrCookie.length < 1)
						continue;*/
					
					//.domain_name_cookie
					//.full_uri_cookie
					//.cookie
					
					add_row_to_jtblCookie_NetworkCapture(node, key);
					
				}
				
						
			}
			
						
			//sort
			resort_interface_jtblCookies_NetworkCapture();
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "update_jtbl_cookies", e);
		}
		
		return false;
		
	}
	
	public static boolean add_row_to_jtblCookie_NetworkCapture(SOURCE node, String key)
	{
		try
		{
			domain_name_cookie = "";
			full_uri_cookie = "";
			cookie = "";
			
			if(key.contains(","))
			{
				cookie = key.substring(0, key.indexOf(","));
				full_uri_cookie = key.substring(key.lastIndexOf(",") + 1, key.length()-1);
				domain_name_cookie = normalize_lookup(full_uri_cookie, false);
			}
			else
				cookie = key;
			
			arrJTblCookie = new String[6];
			
			arrJTblCookie[0] = node.src_ip;
			arrJTblCookie[1] = node.src_mac;
			arrJTblCookie[2] = node.oui;
			arrJTblCookie[3] = cookie;
			arrJTblCookie[4] = domain_name_cookie;
			arrJTblCookie[5] = full_uri_cookie;
			
			intrface.jtblCookies_NetworkCapture.addRow(arrJTblCookie);
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "add_row_to_jtblCookie", e);
		}
		
		return false;
	}
	
	public boolean write_protocol_summary(String delimiter)
	{
		try
		{
			if(SOURCE.TREE_SOURCE_NODES == null || SOURCE.TREE_SOURCE_NODES.isEmpty())
			{
				driver.directive("PUNT! No nodes have been processed yet...");
				return false;
			}
			
			if(!Log.logging_enabled)
			{
				driver.directive("\nPUNT! LOGGING IS DISABLED. You must first enable logging in order to continue");
				return false;				
			}
			
			Log summary_log = new Log("parser/summary_log/",  "summary_log", 250, 999999999);
			
			driver.directive("Writing Protocol Summary to --> " + summary_log.fleLogFile.getCanonicalPath());
			
			
			
			//write header
			String header = "SOURCE " + delimiter + "MAC " + delimiter + "FIRST_CONTACT" + delimiter + "LAST_CONTACT" + delimiter;
			
			for(String hdr : SOURCE.tree_protocol_header_names.values())
				header = header + hdr + delimiter;
			
			summary_log.log_directly(header);
			
			//write totals
			summary_log.log_directly(get_packet_count_summary(delimiter, false));
			
			//write individual node details
			for(SOURCE node : SOURCE.TREE_SOURCE_NODES.values())
			{
				if(node == null)
					continue;
				
				summary_log.log_directly(node.get_protocol_summary(delimiter, false));
			}
			
			summary_log.close_and_open_log_file();
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_protocol_summary", e);
		}
		
		return false;
	}
	
	public String get_packet_count_summary(String delimiter, boolean include_header_name)
	{
		//write totals
		try
		{
			tmp_packet_count.clear();
			this.tmp_packet_count_OVERFLOW.clear();
			int value = 0;
			String summary = "packet summary" + delimiter + " " + delimiter + " " + delimiter + " " + delimiter;
			
			for(String hdr : SOURCE.tree_protocol_header_names.values())
			{		
				try
				{
					value = 0;
					
					for(SOURCE node : SOURCE.TREE_SOURCE_NODES.values())
					{
						if(value >= (Integer.MAX_VALUE-9999))
						{
							tmp_packet_count.put(hdr, 0);
							tmp_packet_count_OVERFLOW.put(hdr, (tmp_packet_count_OVERFLOW.get(hdr)+1));
						}
						
						if(!node.tree_packet_count.containsKey(hdr))
							continue;
						
						//otw
						value += node.tree_packet_count.get(hdr);
						tmp_packet_count.put(hdr, value);
					}
					
					if(include_header_name)					
						summary = summary +  hdr + ": " + value + delimiter;
					else
						summary = summary +  value + delimiter;
				}
				
				catch(Exception e)
				{
					continue;
				}
			}
			
			//finally, put the string together!
			return summary;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "get_packet_count_summary", e);
		}
		
		return "- - - ";
	}
	
	public boolean exit()
	{
		try
		{
			driver.directive("\nProgram Terminated.");
			
			LinkedList<ThdSensorSocket> list = new LinkedList<ThdSensorSocket>();
			LinkedList<ThdParserSocket> list_parser = new LinkedList<ThdParserSocket>();
			
			for(ThdSensorSocket skt : list)
			{
				try
				{
					skt.close_socket();
				}
				catch(Exception e)
				{
					continue;
				}
			}
			
			for(ThdParserSocket skt : list_parser)
			{
				try
				{
					skt.close_socket();
				}
				catch(Exception e)
				{
					continue;
				}
			}
			
			System.exit(0);
			
			return true;
		}
		 catch(Exception e)
		{
			 driver.eop(myClassName, "exit", e);
		}
		
		return false;
	}
	
	public boolean disconnect_all()
	{
		try
		{
			driver.directive("executing disconnection actions...");
			
			while(ThdSensorSocket.ALL_CONNECTIONS.size() > 0)
			{
				try
				{					
					ThdSensorSocket thd = ThdSensorSocket.ALL_CONNECTIONS.removeFirst();					
					thd.close_socket();
				}
				catch(Exception e)
				{
					continue;
				}
			}
			
			while(ThdParserSocket.ALL_CONNECTIONS.size() > 0)
			{
				try
				{					
					ThdParserSocket thd = ThdParserSocket.ALL_CONNECTIONS.removeFirst();					
					thd.close_socket();
				}
				catch(Exception e)
				{
					continue;
				}
			}
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "disconnect_all", e);
		}
		
		return false;
	}
	
	public boolean toggle_logging()
	{
		try
		{
			Log.toggle_logging();
			
			if(intrface != null)
				intrface.jpnlHeap.jcbLoggingEnabled.setSelected(Log.logging_enabled);
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "toggle_logging", e);
		}
		
		return false;
	}
	
	public static boolean set_encryption(String key)
	{
		boolean previous_output_state = driver.output_enabled;
		
		try
		{
			//disable output
			driver.output_enabled = false;
			
			if(key == null || key.trim().equals(""))
			{
				driver.directive("\nENCRYPTION HAS BEEN DISABLED!");	
				
				Start.encryption_key = null;
				
				if(intrface != null)
				{
					intrface.jpnlHeap.jlblEncryptionKey.setText(" Encryption Key: //NOT SET//");
					intrface.jpnlHeap.jlblEncryptionKey.setToolTipText(" Encryption Key: //NOT SET//");
				}
			}
			
			if(key != null && key.trim().equalsIgnoreCase("null"))
			{
				driver.directive("\n\nNOTE: your [null] parameter is a reserved word with this encryption command specifying to disable encryption");
				
				driver.directive("ENCRYPTION HAS BEEN DISABLED!");	
				
				Start.encryption_key = null;
				
				if(intrface != null)
				{
					intrface.jpnlHeap.jlblEncryptionKey.setText(" Encryption Key: //NOT SET//");
					intrface.jpnlHeap.jlblEncryptionKey.setToolTipText(" Encryption Key: //NOT SET//");
				}
			}
			
			if(key != null)
			{
				key = key.trim();
				
				Start.encryption_key = key;
				
				driver.directive("Encryption key has been set to [" + key + "]");
				
				if(intrface != null)
				{
					if(key.length() > 20)
					{
						intrface.jpnlHeap.jlblEncryptionKey.setText(key.substring(0,19));
					}
					else
						intrface.jpnlHeap.jlblEncryptionKey.setText(" Encryption Key: " + key);
					
					intrface.jpnlHeap.jlblEncryptionKey.setToolTipText(" Encryption Key: " + key);
				}
			}
			
			
			
		
			
			
			
			//set the encryption keys!
			
			for(Sensor sensor : Sensor.list_sensors)
			{
				try
				{
					if(key == null || key.trim().equals(""))
					{
						sensor.ENCRYPTION = null;	
					}
					else
					{
						//set the new key!
						sensor.ENCRYPTION = new Encryption(key, Encryption.default_iv_value);
					}
					
				}
				catch(Exception e)
				{
					continue;
				}
			}
			
			for(ThdParserSocket thd : ThdParserSocket.ALL_CONNECTIONS)
			{
				try
				{
					if(key == null || key.trim().equals(""))
					{
						thd.ENCRYPTION = null;	
					}
					else
					{
						//set the new key!
						thd.ENCRYPTION = new Encryption(key, Encryption.default_iv_value);
					}					
				}
				catch(Exception e)
				{
					continue;
				}
			}
			
			for(ResolutionRequest_ThdSocket thd : ResolutionRequest_ThdSocket.ALL_CONNECTIONS)
			{
				try
				{
					if(key == null || key.trim().equals(""))
					{
						thd.ENCRYPTION = null;	
					}
					else
					{
						//set the new key!
						thd.ENCRYPTION = new Encryption(key, Encryption.default_iv_value);
					}					
				}
				catch(Exception e)
				{
					continue;
				}
			}
			
			driver.output_enabled = previous_output_state;
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "set_encryption", e);
		}
		
		
		driver.output_enabled = previous_output_state;
		
		return true;
	}
	
	public boolean toggle_verbose_sensor()
	{
		try
		{
			driver.sensor_output_enabled = !driver.sensor_output_enabled;
			
			if(driver.sensor_output_enabled)
				driver.directive("Sensor output is enabled.");
			else
				driver.directive("Sensor output is disabled.");
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "toggle_verbose_sensor", e);
		}
		
		return false;
	}
	
	public boolean toggle_verbose_parser()
	{
		try
		{
			driver.parser_output_enabled = !driver.parser_output_enabled;
			
			if(driver.parser_output_enabled)
				driver.directive("parser output is enabled.");
			else
				driver.directive("parser output is disabled.");
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "toggle_verbose_parser", e);
		}
		
		return false;
	}
	
	public boolean establish_server_socket(String port)
	{
		try
		{
			int PORT = Integer.parseInt(port.trim());
			
			if(PORT < 0)
			{
				throw new Exception("PORT number must be greater than 0!");
			}
			
			SensorServerSocket svrskt = new SensorServerSocket(PORT);
			
			return true;
		}
		catch(Exception e)
		{
			driver.directive("ERROR! Invalid port received. Please run command again and specify valid listen port!");
		}
		
		return false;
	}
	
	public boolean parser_connect(String location)
	{
		try
		{
			if(location == null || location.trim().equals(""))
			{
				driver.directive("ERROR! It appears you are missing location parameters for the connect command! Please try again!");
				return false;
			}
			
			location = location.trim();
			
			
			String array [] = null;
			
			if(location.contains(":"))
				array = location.split(":");
			else if(location.contains(","))
				array = location.split(",");
			else 
				array = location.split(" ");
			
			String address = array[0].trim();
			int port = Integer.parseInt(array[1].trim());
			
			if(address.equalsIgnoreCase("localhost") || address.equalsIgnoreCase("local host") || address.equalsIgnoreCase("-localhost") || address.equalsIgnoreCase("-local host"))
				address = "127.0.0.1";
			
			//Connect
			driver.directive("Attempting to connect sensor out to transport data to PARSER --> " + address + " : " + port);
			
			try
			{
				Socket skt = new Socket(address, port);
				
				ThdSensorSocket thd = new ThdSensorSocket(null, skt);
			}
			catch(Exception ee)
			{
				driver.directive("ERROR! I was unable to establish a connection to PARSER at --> " + address + " : " + port);
			}
			
			return true;
		}
		catch(Exception e)
		{
			driver.directive("ERROR! I was expecting command: parser_connect <ip address> <port>\nPlease try again...");
		}
		
		return false;
	}
	
	public static boolean map_source_nodes()
	{
		try
		{
			//update geo
			GEO_Location.update_geo_resolution();
			
			if(SOURCE.TREE_SOURCE_NODES == null || SOURCE.TREE_SOURCE_NODES.isEmpty())
			{
				driver.directive("PUNT! No source nodes have been populated in the system! Unable to complete selected action...");
				return false;
			}
			
			try	{	list_map_details.clear();} catch(Exception e){list_map_details = new LinkedList<Node_Map_Details>();}
			
			for(SOURCE node : SOURCE.TREE_SOURCE_NODES.values())
			{
				if(node.geo == null)
					continue;
				
				list_map_details.add(node.get_map_node(true));
			}
			
			if(list_map_details == null || list_map_details.isEmpty())
			{
				driver.directive("PUNT!!! No source nodes were found to have GEO locations populated yet! Try running update_geo command and ensure you're connected to the Internet.");
				return false;	
			}
			
			//display map!
			GoogleMap map = new GoogleMap("Source Nodes", "source_nodes.html", list_map_details, true, true, 600);
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "map_source_nodes", e);
		}
		
		return false;
	}
	
	public boolean toggle_verbose()
	{
		try
		{
			driver.output_enabled = !Driver.output_enabled;
			
			
			
			Driver.sensor_output_enabled = !Driver.sensor_output_enabled;
			
			if(Driver.sensor_output_enabled)
				driver.directive("Sensor output is enabled!");
			else
				driver.directive("Sensor output is disabled!");
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "toggle_verbose", e);
		}
		
		return false;
	}
	
	public static boolean map_resolution_nodes()
	{
		try
		{
			//update geo
			GEO_Location.update_geo_resolution();
			
			if(Resolution.TREE_RESOURCE == null || Resolution.TREE_RESOURCE.isEmpty())
			{
				driver.directive("***PUNT! No resource nodes have been populated in the system! Unable to complete selected action...");
				return false;
			}
			
			try	{	list_map_details.clear();} catch(Exception e){list_map_details = new LinkedList<Node_Map_Details>();}
			
			for(Resolution node : Resolution.TREE_RESOURCE.values())
			{
				if(node.geo == null)
					continue;
				
				list_map_details.add(node.get_map_node(true));
			}
			
			if(list_map_details == null || list_map_details.isEmpty())
			{
				driver.directive("***PUNT!!! No source nodes were found to have GEO locations populated yet! Try running update_geo command and ensure you're connected to the Internet.");
				return false;	
			}
			
			//display map!
			GoogleMap map = new GoogleMap("Resource [Resolution] Nodes", "resolution_nodes.html", list_map_details, true, true, 600);
									
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "map_resolution_nodes", e);
		}
		
		return false;
	}
	
	public boolean resolution_connect(String location)
	{
		try
		{
			if(location == null || location.trim().equals(""))
			{
				driver.directive("ERROR *  It appears you are missing location parameters for the connect command! Please try again!");
				return false;
			}
			
			location = location.trim();
			
			
			String array [] = null;
			
			if(location.contains(":"))
				array = location.split(":");
			else if(location.contains(","))
				array = location.split(",");
			else 
				array = location.split(" ");
			
			String address = array[0].trim();
			int port = Integer.parseInt(array[1].trim());
			
			if(address.equalsIgnoreCase("localhost") || address.equalsIgnoreCase("local host") || address.equalsIgnoreCase("-localhost") || address.equalsIgnoreCase("-local host"))
				address = "127.0.0.1";
			
			//Connect
			driver.directive("Attempting to connect out to resolution request server --> " + address + " : " + port);
			
			try
			{
				Socket skt = new Socket(address, port);
				
				ResolutionRequest_ThdSocket thd = new ResolutionRequest_ThdSocket(null, skt);
			}
			catch(Exception ee)
			{
				driver.directive("ERROR *  I was unable to establish a connection to resolution request server at --> " + address + " : " + port);
			}
			
			return true;
		}
		catch(Exception e)
		{
			driver.directive("ERROR! I was expecting command: resolution_connect <ip address> <port>\nPlease try again...");
		}
		
		return false;
	}
	
	public static boolean map_connection_markers()
	{
		try
		{
			//update geo
			GEO_Location.update_geo_resolution();
			
			if(Resolution.TREE_RESOURCE == null || Resolution.TREE_RESOURCE.isEmpty())
			{
				driver.directive("* * * * PUNT! No resource nodes have been populated in the system! Unable to complete selected action...");
				return false;
			}
			
			try	{	list_map_details.clear();} catch(Exception e){list_map_details = new LinkedList<Node_Map_Details>();}
			
			for(Resolution node : Resolution.TREE_RESOURCE.values())
			{
				if(node.geo == null)
					continue;
				
				list_map_details.add(node.get_map_node(false));
			}
			
			if(list_map_details == null || list_map_details.isEmpty())
			{
				driver.directive("* * * * PUNT!!! No source nodes were found to have GEO locations populated yet! Try running update_geo command and ensure you're connected to the Internet.");
				return false;	
			}
			
			//display map!
			GoogleMap markers = new GoogleMap(Driver.GEO_LOCATION_ME, "Connections", "connections.html", list_map_details, true, true, 600);
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "map_connection_markers", e);
		}
		
		return false;
	}
	
	public static boolean map_process()
	{
		try
		{
			//update process
			if(Driver.PROCESS_DAEMON != null)
				Driver.PROCESS_DAEMON.process_interrupt();
			
			if(Driver.NETSTAT_DAEMON != null)
				Driver.NETSTAT_DAEMON.process_interrupt();	
			
			//update parents
			Node_Process.update_node_parents();
			Node_Process.update_terminated_processes();
			Node_Netstat.update_netstat_parent();
			Node_Netstat.update_closed_netstats();
			
			GEO_Location.update_geo_resolution();
			
			try	{	list_map_details_process.clear();} catch(Exception ee){list_map_details_process = new LinkedList<Node_Map_Details>();}
			
			list_map_details_process= Node_Process.get_linked_list_of_map_details_from_each_node(false, false);
			
			if(list_map_details_process != null && list_map_details_process.size() > 0 && Driver.GEO_LOCATION_ME != null)
			{
				GoogleMap markers = new GoogleMap(Driver.GEO_LOCATION_ME, "Processes - Running", "processes_running.html", list_map_details_process, true, true, 600);
			}	
			else
				driver.directive("Punt! No GEO locations were discovered yet... Is GEO Orbiter enabled?");
			
			System.gc();
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "map_process", e);
		}
		
		return false;
	}
	
	public boolean sensor_connect(String location)
	{
		try
		{
			if(location == null || location.trim().equals(""))
			{
				//query user for details
				location = driver.jop_Query("Please enter IP address and port number to connect to Sensor", "Enter IP and Port");
				
				if(location == null || location.trim().equals(""))
				{
					driver.directive("ERROR!!! It appears you are missing location parameters for the connect command! Please try again!");
					return false;
				}				
				
			}
			
			location = location.trim();
			
			
			String array [] = null;
			
			if(location.contains(":"))
				array = location.split(":");
			else if(location.contains(","))
				array = location.split(",");
			else 
				array = location.split(" ");
			
			String address = array[0].trim();
			
			if(array.length == 1)
			{
				array = new String[] {address, ""};
				
				//query user for details
				array[1] = driver.jop_Query("Please port number to connect to Sensor", "Enter Port Number");
				
				if(array[1] == null || array[1].trim().equals(""))
				{
					driver.directive("ERROR!!! It appears you are missing port parameters for the connect command! Please try again!");
					return false;
				}	
			}
			driver.directive("out -- " + array[1]);
			int port = Integer.parseInt(array[1].trim());
			
			if(address.equalsIgnoreCase("localhost") || address.equalsIgnoreCase("local host") || address.equalsIgnoreCase("-localhost") || address.equalsIgnoreCase("-local host"))
				address = "127.0.0.1";
			
			//start parser threads
			for(int i = 0; i < ParserServerSocket.NUM_PARSER_THREADS && Parser.list_parsers.size() < ParserServerSocket.NUM_PARSER_THREADS; i++)
			{
				Parser.list_parsers.add(new Parser());
			}
			
			//Connect
			driver.directive("Attempting to connect parser to retrieve data from SENSOR --> " + address + " : " + port);
			
			try
			{
				Socket skt = new Socket(address, port);
				
				ThdParserSocket thd = new ThdParserSocket(null, skt);
			}
			catch(Exception ee)
			{
				driver.directive("ERROR! I was unable to establish a connection to SENSOR at --> " + address + " : " + port);
			}
			
			return true;
		}
		catch(Exception e)
		{
			driver.directive("ERROR! I was expecting command: sensor_connect <ip address> <port>\nPlease try again...");
		}
		
		return false;
	}
	
	public boolean display_status()
	{
		try
		{
			driver.directive("\n /////////// STATUS ////////////");
			driver.directive(driver.FULL_NAME);
			
			driver.directive("");
			driver.directive("Time of First Start: " + driver.TIME_OF_FIRST_START);
			
			if(Start.encryption_key == null)
				driver.directive("Encryption Key --> " + "//NOT SET//");
			else
				driver.directive("Encryption Key --> " + Start.encryption_key);
			
			driver.directive("Sensor Name --> " + Start.sensor_name);
			
			driver.directive("Verbose is enabled: " + driver.output_enabled);
			driver.directive("Sensor Verbose is enabled: " + driver.sensor_output_enabled);
			driver.directive("Parser Verbose is enabled: " + driver.parser_output_enabled);
			
			if(driver.PID != null && !driver.PID.trim().equals(""))
			{
				driver.directive("PID: " + driver.PID);
				driver.directive("HOST NAME: " + driver.HOST_NAME);
			}
			
			if((SensorServerSocket.list_server_sockets == null || SensorServerSocket.list_server_sockets.isEmpty()) && (ParserServerSocket.list_server_sockets == null || ParserServerSocket.list_server_sockets.isEmpty()))
			{
				driver.directive("No server sockets instantiated yet!");
			}
			else
			{
				for(SensorServerSocket svrskt : SensorServerSocket.list_server_sockets)
				{
					driver.directive("Sensor ServerSocket --> " + svrskt.get_status());
				}
				
				for(ParserServerSocket svrskt : ParserServerSocket.list_server_sockets)
				{
					driver.directive("Parser ServerSocket --> " + svrskt.get_status());
				}
			}
			
			if(ThdSensorSocket.list_outbound_connections != null && !ThdSensorSocket.list_outbound_connections.isEmpty())
			{
				driver.directive("Num Outbound Sensor Socket connections: " + ThdSensorSocket.list_outbound_connections.size());
				
				for(ThdSensorSocket thd : ThdSensorSocket.list_outbound_connections)
				{
					driver.directive("\tOutbound Sensor Socket -->" + thd.CONNECTION_ADDRESS);
				}
			}
			
			if(ThdParserSocket.list_outbound_connections != null && !ThdParserSocket.list_outbound_connections.isEmpty())
			{
				driver.directive("Num Outbound Parser Socket connections: " + ThdParserSocket.list_outbound_connections.size());
				
				for(ThdParserSocket thd : ThdParserSocket.list_outbound_connections)
				{
					driver.directive("\tOutbound Parser Socket -->" + thd.CONNECTION_ADDRESS);
				}
			}
			
			if((ResolutionRequest_ServerSocket.list_server_sockets != null && !ResolutionRequest_ServerSocket.list_server_sockets.isEmpty()))
			{
				for(ResolutionRequest_ServerSocket svrskt : ResolutionRequest_ServerSocket.list_server_sockets)
				{
					driver.directive("Request Resolution ServerSocket --> " + svrskt.get_status());
				}
			}
			
			driver.directive("");
			if(Parser.log != null)
				driver.directive("Parser Log: " + Parser.log.logging_path);
			
			if(Parser.log_dns != null)
				driver.directive("DNS Log: " + Parser.log_dns.logging_path);
			
			driver.directive("");			
			driver.directive("Heap Size: " + Runtime.getRuntime().totalMemory()/1e6 + "(MB) Max Heap Size: " + Runtime.getRuntime().maxMemory()/1e6 + "(MB) Free Heap Size: " + Runtime.getRuntime().freeMemory()/1e6 + "(MB) Consumed Heap Size: " + (Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory())/1e6 + "(MB)");
			driver.directive("");	
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "display_status", e);
		}
		
		return false;
	}
	
	
	public static boolean monitor_selected_node_in_network_summary()
	{
		try
		{
			if(StandardInListener.intrface == null)
			{
				driver.jop_Error("No nodes are populated yet!", false);
				return false;
			}
			
			if(SOURCE.TREE_SOURCE_NODES == null || SOURCE.TREE_SOURCE_NODES.isEmpty())
			{
				driver.jop_Error("No nodes are populated yet!!!", false);
				return false;
			}
			
			selected_row_id = StandardInListener.intrface.jtblSourceNodes.getSeletedRow_ID();
			
			if(selected_row_id == null || selected_row_id.trim().equals("") || selected_row_id.trim().equalsIgnoreCase("null"))
			{
				driver.jop_Error("Punt! Please select a valid node to continue...", false);
				return false;
			}
			
			selected_row_id = selected_row_id.trim();
			
			//get the selected node
			if(!SOURCE.TREE_SOURCE_NODES.containsKey(selected_row_id))
			{
				driver.jop_Error("Punt! I could not find node ID [" + selected_row_id + "] in the system...", false);
				return false;
			}
			
			selected_node_to_monitor = SOURCE.TREE_SOURCE_NODES.get(selected_row_id);
			
			if(selected_node_to_monitor == null)
			{
				driver.jop_Error("Punt!!! I could not find node ID [" + selected_row_id + "] in the system...", false);
				return false;
			}
			
			//update the system to populate based on this selected node
			intrface.bar_NODE_statistics.myTitle = "NODE Statistics [" + selected_node_to_monitor.src_ip + "]";
			intrface.bar_NODE_statistics.need_to_update_title = true;
			//intrface.bar_NODE_statistics.barChart.setTitle(intrface.bar_NODE_statistics.myTitle);
			
			intrface.pie_NODE_statistics.myTitle = "NODE Statistics [" + selected_node_to_monitor.src_ip + "]";
			intrface.pie_NODE_statistics.need_to_update_title = true;
			//intrface.pie_NODE_statistics.pieChart.setTitle(intrface.pie_NODE_statistics.myTitle);
			
			//indiacte we should make an update
			selected_node_to_monitor.updated_packet_count = true;
			
			//done here selecting the node, now call the update
			update_selected_node_statistics();
			
			intrface.bar_NODE_statistics.validate();			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "monitor_selected_node_in_network_summary", e);
		}
		
		return false;
	}
	
	
	public static boolean update_selected_node_statistics()
	{
		try
		{
			if(StandardInListener.intrface == null)
				return false;
			
			if(selected_node_to_monitor == null)
				return false;
			
			if(selected_node_to_monitor.tree_packet_count == null || selected_node_to_monitor.tree_packet_count.isEmpty())
				return false;
			
			if(!selected_node_to_monitor.updated_packet_count)
				return true;
			
			//set false until next update from parser
			selected_node_to_monitor.updated_packet_count = false;
			
			//
			//POPULATE ARRAYS
			//
			arrNames_selected_node_to_monitor = new String	[selected_node_to_monitor.tree_packet_count.size()];
			arrValues_selected_node_to_monitor = new int	[selected_node_to_monitor.tree_packet_count.size()];
			
			k = 0;
			for(String key : selected_node_to_monitor.tree_packet_count.keySet())
			{
				if(key == null || key.trim().equals(""))
					continue;
				
				arrNames_selected_node_to_monitor[k] = key;
				arrValues_selected_node_to_monitor[k] = selected_node_to_monitor.tree_packet_count.get(key);
				
				++k;
			}
			
			//
			//UPDATE GRAPHS
			//
			//just call one, it will update the other
			StandardInListener.intrface.pie_NODE_statistics.display_data(arrNames_selected_node_to_monitor, arrValues_selected_node_to_monitor, true);
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "update_selected_node_statistics", e);			
		}
		
		return false;
		
	}
	
	public static boolean update_resource_statistics()
	{
		try
		{
			if(StandardInListener.intrface == null)
				return false;
			
			if(Resolution.TREE_RESOURCE == null || Resolution.TREE_RESOURCE.isEmpty())
				return false;
			
			//Get the list of unique resources first. bigO(n^2)... sorry about that! - solomonSonya... I'll optimize later
			try	{	list_unique_resolution_EXTERNAL.clear();}	catch(Exception e){list_unique_resolution_EXTERNAL = new LinkedList<Resolution>();}
			try	{	list_unique_resolution_INTERNAL.clear();}	catch(Exception e){list_unique_resolution_INTERNAL = new LinkedList<Resolution>();}
			
			for(Resolution resource : Resolution.TREE_RESOURCE.values())
			{
				if(resource == null)
					continue;
				
				if(list_unique_resolution_EXTERNAL.contains(resource))
					continue;
					
				//determine to store the node
				if(resource.is_private_non_routable_address || resource.is_private_non_routable_ip)
				{
					if(list_unique_resolution_INTERNAL.contains(resource))
						continue;
					
					list_unique_resolution_INTERNAL.add(resource);
				}
				else	//external			
				{
					if(list_unique_resolution_EXTERNAL.contains(resource))
						continue;
					
					//otw, add
					list_unique_resolution_EXTERNAL.add(resource);
					
					
				}
			}
						
			if(list_unique_resolution_EXTERNAL != null && list_unique_resolution_EXTERNAL.size() > 0)
			{
				//sort the list
				Collections.sort(list_unique_resolution_EXTERNAL, new Comparator<Resolution>()
				{
					public int compare(Resolution r1, Resolution r2)
					{
						return r2.tree_source.size() - r1.tree_source.size();
					}						
					
				});
			}
			
			if(list_unique_resolution_INTERNAL != null && list_unique_resolution_INTERNAL.size() > 0)
			{
				//sort the list
				Collections.sort(list_unique_resolution_INTERNAL, new Comparator<Resolution>()
				{
					public int compare(Resolution r1, Resolution r2)
					{
						return r2.tree_source.size() - r1.tree_source.size();
					}						
					
				});
			}
			
//			//now with the right nodes, initialize the names and values
//			arrNames_resource_external = new String[list_unique_resolution_EXTERNAL.size()];
//			arrValues_resource_external = new int[list_unique_resolution_EXTERNAL.size()];
//			
//			//populate
//			l = 0;
//			for(Resolution resource : list_unique_resolution_EXTERNAL)
//			{
//				if(resource == null)
//					continue;
//				
//				if(resource.domain_name != null && !resource.domain_name.trim().equals(""))
//				{
//					arrNames_resource_external[l] = resource.domain_name;
//					arrValues_resource_external[l] = resource.tree_source.size();
//				}
//				
//				else
//				{
//					//check if we can get the first domain name from the list
//					if(resource.list_dns_query_names != null && !resource.list_dns_query_names.isEmpty())
//						arrNames_resource_external[l] =	resource.list_dns_query_names.getFirst();					
//					
//					//check address
//					else if(resource.address != null && !resource.address.trim().equals(""))
//						arrNames_resource_external[l] =	resource.address;
//					
//					//check list of ip addresses
//					else if(resource.list_dns_response_addresses != null && !resource.list_dns_response_addresses.isEmpty())
//						arrNames_resource_external[l] =	resource.list_dns_response_addresses.getFirst();
//					
//					else//unknown!
//					arrNames_resource_external[l] = "other";
//					
//					//populate value!
//					arrValues_resource_external[l] = resource.tree_source.size();
//					
//				}
//					
//				++l;
//			}
			
			initialize_names_and_values_external();
			initialize_names_and_values_internal();
			
			return true;
		}
		
		catch(Exception e)
		{
			driver.eop(myClassName, "update_resource_statistics", e);
		}
		
		return false;
		
	}
	
	public static boolean initialize_names_and_values_external()
	{
		try
		{
			if(list_unique_resolution_EXTERNAL == null || list_unique_resolution_EXTERNAL.isEmpty())
				return false;
			
			//now with the right nodes, initialize the names and values
			arrNames_resource_external = new String[list_unique_resolution_EXTERNAL.size()];
			arrValues_resource_external = new int[list_unique_resolution_EXTERNAL.size()];
			
			//populate
			l = 0;
			for(Resolution resource : list_unique_resolution_EXTERNAL)
			{
				if(resource == null)
					continue;
				
				if(resource.domain_name != null && !resource.domain_name.trim().equals(""))
				{
					arrNames_resource_external[l] = resource.domain_name;
					arrValues_resource_external[l] = resource.tree_source.size();
				}
				
				else
				{
					//check if we can get the first domain name from the list
					if(resource.list_dns_query_names != null && !resource.list_dns_query_names.isEmpty())
						arrNames_resource_external[l] =	resource.list_dns_query_names.getFirst();					
					
					//check address
					else if(resource.address != null && !resource.address.trim().equals(""))
						arrNames_resource_external[l] =	resource.address;
					
					//check list of ip addresses
					else if(resource.list_dns_response_addresses != null && !resource.list_dns_response_addresses.isEmpty())
						arrNames_resource_external[l] =	resource.list_dns_response_addresses.getFirst();
					
					else//unknown!
					arrNames_resource_external[l] = "other";
					
					//populate value!
					arrValues_resource_external[l] = resource.tree_source.size();
					
				}
					
				++l;
			}
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "initialize_names_and_values_external");
		}
		
		return false;
	}
	
	public static boolean initialize_names_and_values_internal()
	{
		try
		{
			if(list_unique_resolution_INTERNAL == null || list_unique_resolution_INTERNAL.isEmpty())
				return false;
			
			//now with the right nodes, initialize the names and values
			arrNames_resource_internal = new String[list_unique_resolution_INTERNAL.size()];
			arrValues_resource_internal = new int[list_unique_resolution_INTERNAL.size()];
			
			//populate
			l = 0;
			for(Resolution resource : list_unique_resolution_INTERNAL)
			{
				if(resource == null)
					continue;
				
				if(resource.domain_name != null && !resource.domain_name.trim().equals(""))
				{
					arrNames_resource_internal[l] = resource.domain_name;
					arrValues_resource_internal[l] = resource.tree_source.size();
				}
				
				else
				{
					//check if we can get the first domain name from the list
					if(resource.list_dns_query_names != null && !resource.list_dns_query_names.isEmpty())
						arrNames_resource_internal[l] =	resource.list_dns_query_names.getFirst();					
					
					//check address
					else if(resource.address != null && !resource.address.trim().equals(""))
						arrNames_resource_internal[l] =	resource.address;
					
					//check list of ip addresses
					else if(resource.list_dns_response_addresses != null && !resource.list_dns_response_addresses.isEmpty())
						arrNames_resource_internal[l] =	resource.list_dns_response_addresses.getFirst();
					
					else//unknown!
					arrNames_resource_internal[l] = "other";
					
					//populate value!
					arrValues_resource_internal[l] = resource.tree_source.size();
					
				}
					
				++l;
			}
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "initialize_names_and_values_internal");
		}
		
		return false;
	}
	
//	public static boolean initialize_names_and_values(String [] names, int [] values, LinkedList<Resolution> list, boolean internal)
//	{
//		try
//		{
//			
//			
//			//now with the right nodes, initialize the names and values
//			arrNames_resource_external = new String[list_unique_resolution_EXTERNAL.size()];
//			arrValues_resource_external = new int[list_unique_resolution_EXTERNAL.size()];
//			
//			//populate
//			l = 0;
//			for(Resolution resource : list_unique_resolution_EXTERNAL)
//			{
//				if(resource == null)
//					continue;
//				
//				if(resource.domain_name != null && !resource.domain_name.trim().equals(""))
//				{
//					arrNames_resource_external[l] = resource.domain_name;
//					arrValues_resource_external[l] = resource.tree_source.size();
//				}
//				
//				else
//				{
//					//check if we can get the first domain name from the list
//					if(resource.list_dns_query_names != null && !resource.list_dns_query_names.isEmpty())
//						arrNames_resource_external[l] =	resource.list_dns_query_names.getFirst();					
//					
//					//check address
//					else if(resource.address != null && !resource.address.trim().equals(""))
//						arrNames_resource_external[l] =	resource.address;
//					
//					//check list of ip addresses
//					else if(resource.list_dns_response_addresses != null && !resource.list_dns_response_addresses.isEmpty())
//						arrNames_resource_external[l] =	resource.list_dns_response_addresses.getFirst();
//					
//					else//unknown!
//					arrNames_resource_external[l] = "other";
//					
//					//populate value!
//					arrValues_resource_external[l] = resource.tree_source.size();
//					
//				}
//					
//				++l;
//			}
//			
//			return true;
//		}
//		catch(Exception e)
//		{
//			driver.eop(myClassName, "initialize_names_and_values");
//		}
//		
//		return false;
//	}
	
	public static boolean update_PIE_resource_statistics_EXTERNAL(boolean update_corresponding_bar_chart_if_applicable)
	{
		try
		{
			update_resource_statistics();
			
			//update!
			StandardInListener.intrface.pie_RESOURCE_statistics_EXTERNAL.display_data(arrNames_resource_external, arrValues_resource_external, update_corresponding_bar_chart_if_applicable);
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "update_PIE_resource_statistics_EXTERNAL", e);
		}
		
		return false;
	}
	
	public static boolean update_BAR_resource_statistics_EXTERNAL()
	{
		try
		{
			update_resource_statistics();
			
			//update!
			StandardInListener.intrface.bar_RESOURCE_statistics_EXTERNAL.display_data(arrNames_resource_external, arrValues_resource_external);
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "update_BAR_resource_statistics_EXTERNAL", e);
		}
		
		return false;
	}
	
	public static boolean update_PIE_resource_statistics_INTERNAL(boolean update_corresponding_bar_chart_if_applicable, boolean update_resource_statistics)
	{
		try
		{
			if(update_resource_statistics)
				update_resource_statistics();
			
			//update!
			StandardInListener.intrface.pie_RESOURCE_statistics_INTERNAL.display_data(arrNames_resource_internal, arrValues_resource_internal, update_corresponding_bar_chart_if_applicable);
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "update_PIE_resource_statistics_EXTERNAL", e);
		}
		
		return false;
	}
	
	public static boolean update_cookies_host_system(boolean notify_user_of_empty_cookies, boolean open_database)
	{
		try
		{
			
			intrface.jtblCookies_HostSystem.removeAllRows();
			
			
			if(notify_user_of_empty_cookies && !driver.isWindows)
			{
				driver.jop_Error("Punt! Cookies Enumeration not configured for this system yet...", false);
				return false;
			}
			
			if(open_database)
				Cookie_Container_Host_System.update_cookies_host_system(notify_user_of_empty_cookies);
			
			//
			//add rows to jtable
			//
			for(Cookie_Object_Host_System cookie : Cookie_Container_Host_System.list_COOKIES)
			{
				intrface.jtblCookies_HostSystem.addRow(cookie.get_jtable_row());
			}
				
		
			
			 
			System.gc();
			
			return true;
		}
		
		catch(Exception e)
		{
			driver.eop(myClassName, "update_cookies_host_system", e);
		}
		
		return false;
	}
	
	public static boolean update_BAR_resource_statistics_INTERNAL()
	{
		try
		{
			update_resource_statistics();
			
			//update!
			StandardInListener.intrface.bar_RESOURCE_statistics_INTERNAL.display_data(arrNames_resource_internal, arrValues_resource_internal);
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "update_BAR_resource_statistics_INTERNAL", e);
		}
		
		return false;
	}
	
	
	public static String normalize_lookup(String lookup, boolean drop_subdomains)
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
			if(drop_subdomains)
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

