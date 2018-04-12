/**
 * This thread is just to help with repetitive tasks 
 * 
 *  @author Solomon Sonya
 */

package Worker;

import Driver.*;
import OUI_Parser.Node_OUI;
import OUI_Parser.Node_OUI_Container_GUI;
import GEO_Location.*;
import java.awt.event.*;
import java.net.InetAddress;

import Parser.*;
import javax.swing.Timer;
import Profile.*;
import nmap.NMap;

import java.util.*;


public class ThdWorker extends Thread implements Runnable, ActionListener
{
	public static Driver driver = new Driver();
	public static final String myClassName = "ThdWorker";
	
	public volatile Timer tmrUpdate_1_SEC = null;
	public volatile Timer tmrUpdate_5_SEC = null;
	public volatile Timer tmrUpdate_10_SEC = null;	
	public volatile Timer tmrUpdate_60_SEC = null;
	public volatile Timer tmrUpdate_60_MINS = null;
	public volatile Timer tmrUpdate_10_MINS = null;
	
	public volatile boolean handle_interrupt_1_SEC = true;
	public volatile boolean handle_interrupt_5_SEC = true;
	public volatile boolean handle_interrupt_10_SEC = true;
	public volatile boolean handle_interrupt_60_SEC = true;
	public volatile boolean handle_interrupt_60_MINS = true;
	public volatile boolean handle_interrupt_10_MINS = true;
	
	public static volatile boolean refresh_jtable_protocol = false;
	public static volatile boolean refresh_jtable_resolution = false;
	
	/*public static volatile LinkedList<Resolution> list_resolve_resolution = new LinkedList<Resolution>();
	public volatile Resolution resolution = null;*/
	
	public ThdWorker()
	{
		try
		{
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
			//start timers
			tmrUpdate_1_SEC = new Timer(1000, this);
			tmrUpdate_1_SEC.start();
			
			tmrUpdate_5_SEC = new Timer(5000, this);
			tmrUpdate_5_SEC.start();
			
			tmrUpdate_10_SEC = new Timer(10000, this);
			tmrUpdate_10_SEC.start(); 
			
			tmrUpdate_60_SEC = new Timer(60000, this);
			tmrUpdate_60_SEC.start();
			
			tmrUpdate_10_MINS = new Timer(60000*10, this);
			tmrUpdate_10_MINS.start();
			
			tmrUpdate_60_MINS = new Timer(60000*60, this);
			tmrUpdate_60_MINS.start();
			
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
			if(ae.getSource() == this.tmrUpdate_1_SEC && this.handle_interrupt_1_SEC)
			{
				processInterrupt_1_SEC();
			}
			
			else if(ae.getSource() == this.tmrUpdate_5_SEC && this.handle_interrupt_5_SEC)
			{
				processInterrupt_5_SEC();
			}
			
			else if(ae.getSource() == this.tmrUpdate_10_SEC && this.handle_interrupt_10_SEC)
			{
				processInterrupt_10_SEC();
			}
			
			else if(ae.getSource() == this.tmrUpdate_60_SEC && this.handle_interrupt_60_SEC)
			{
				processInterrupt_60_SEC();
			}
			
			else if(ae.getSource() == this.tmrUpdate_10_MINS && this.handle_interrupt_10_MINS)
			{
				processInterrupt_10_MINS();
			}
			
			else if(ae.getSource() == this.tmrUpdate_60_MINS && this.handle_interrupt_60_MINS)
			{
				processInterrupt_60_MINS();
			}
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "ae", e);
		}
	}
	
	public boolean processInterrupt_1_SEC()
	{
		try
		{
			if(!handle_interrupt_1_SEC)
				return true;
			//
			//lock semaphone
			//
			handle_interrupt_1_SEC = false;
			
			//
			//WORK
			//			
			//if(!list_resolve_resolution.isEmpty())
				//process_resolution_list();
				
			
			
			//
			//release semaphore
			//
			this.handle_interrupt_1_SEC = true;
			return true;
		}
		catch(ConcurrentModificationException cme)
		{
			driver.directive("* Holdfast, I'm updating the resolution list...");
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "processInterrupt_1_SEC", e);
		}
		
		//
		//release semaphore
		//
		this.handle_interrupt_1_SEC = true;
		return false;
	}
	
	//////////////////////////////////////////////////////
	//////////////////////////////////////////////////////
	//////////////////////////////////////////////////////
	//////////////////////////////////////////////////////
	
	public boolean processInterrupt_5_SEC()
	{
		try
		{
			if(!handle_interrupt_5_SEC)
				return true;
			//
			//lock semaphone
			//
			handle_interrupt_5_SEC = false;
			
			//
			//WORK
			//	
			if(refresh_jtable_protocol)
			{
				update_jtable_protocol();
				
				StandardInListener.update_PIE_overall_network_statistics(true);				
				
				if(StandardInListener.intrface != null && !StandardInListener.intrface.bar_network_statistics.jcbEnableChart.isSelected())
					StandardInListener.update_BAR_overall_network_statistics();
				
				//update if there's a thread to monitor
				StandardInListener.update_selected_node_statistics();
				
				update_jtable_resolution();
				
				refresh_jtable_protocol = false;
			}
			
			
			
			if(Resolution.updated_data_refresh_required)
			{
				StandardInListener.update_PIE_resource_statistics_EXTERNAL(true);
				
				StandardInListener.update_PIE_resource_statistics_INTERNAL(true, false);
				
				Resolution.updated_data_refresh_required = false;
			}
			
			if(Application.update_network)
			{
				StandardInListener.update_jtbl_application(true);
				
				Application.update_network = false;
			}
			
			if(SOURCE.update_cookies_needed)
			{
				StandardInListener.update_jtbl_cookies();
				
				SOURCE.update_cookies_needed = false;
			}
			
			if(NMap.update_required)
			{
				StandardInListener.intrface.update_jtblNetworkMap();
				NMap.update_required = false;
			}
			
			if(Node_OUI.updated_required)
			{
				Node_OUI.updated_required = false;
				StandardInListener.intrface.update_jtblOUI_in_use();
				
				//update pie charts
				Node_OUI_Container_GUI.update_names_and_values();
				StandardInListener.intrface.pie_devices_on_network.display_data(Node_OUI_Container_GUI.arrNames, Node_OUI_Container_GUI.arrValues, true);
				
			}
			
			StandardInListener.intrface.update_packet_summary_snapshot();
			
			//
			//release semaphore
			//
			this.handle_interrupt_5_SEC = true;
			return true;
		}
		
		catch(Exception e)
		{
			driver.eop(myClassName, "processInterrupt_5_SEC", e);
		}
		
		//
		//release semaphore
		//
		this.handle_interrupt_5_SEC = true;
		return false;
	}
	
	
		
	//////////////////////////////////////////////////////
	//////////////////////////////////////////////////////
	//////////////////////////////////////////////////////
	//////////////////////////////////////////////////////
	
	public boolean processInterrupt_10_SEC()
	{
		try
		{
			if(!handle_interrupt_10_SEC)
				return true;
			//
			//lock semaphone
			//
			handle_interrupt_10_SEC = false;
			
			//
			//WORK
			//			
			//driver.sop("ready to process intr 10 sec... " + driver.time.getTime_Current(":", true));
			
			
			
			//
			//release semaphore
			//
			this.handle_interrupt_10_SEC = true;
			return true;
		}
		
		catch(Exception e)
		{
			driver.eop(myClassName, "processInterrupt_10_SEC", e);
		}
		
		//
		//release semaphore
		//
		this.handle_interrupt_10_SEC = true;
		return false;
	}
		
		
		
		
		
	//////////////////////////////////////////////////////
	//////////////////////////////////////////////////////
	//////////////////////////////////////////////////////
	//////////////////////////////////////////////////////
		
	public boolean processInterrupt_60_SEC()
	{
		try
		{
			if(!handle_interrupt_60_SEC)
				return true;
			//
			//lock semaphone
			//
			handle_interrupt_60_SEC = false;
			
			//
			//WORK
			//			
			
			//show status for nmap agents:
			try
			{
				if(NMap.list_working_nmap_daemons != null && !NMap.list_working_nmap_daemons.isEmpty())
				{
					for(int i = 0; i < NMap.list_working_nmap_daemons.size(); i++)
					{
						NMap.list_working_nmap_daemons.get(i).pwOut.println("status");
						NMap.list_working_nmap_daemons.get(i).pwOut.flush();
					}
				}
			}
			catch(Exception e){}
			
			//
			//GC
			//
			System.gc();
			
			//
			//Update OUI
			//
			//driver.driver_oui.update_MAC_Registration_Data();
			
			//
			//Update GEO
			//
			//driver.driver_geo.updateSSID();
			
			
			//
			//release semaphore
			//
			this.handle_interrupt_60_SEC = true;
			return true;
		}
		
		catch(Exception e)
		{
			driver.eop(myClassName, "processInterrupt_60_SEC", e);
		}
		
		//
		//release semaphore
		//
		this.handle_interrupt_60_SEC = true;
		return false;
	}	
		
		

	//////////////////////////////////////////////////////
	//////////////////////////////////////////////////////
	//////////////////////////////////////////////////////
	//////////////////////////////////////////////////////

	public boolean processInterrupt_10_MINS()
	{
		try
		{
			if(!handle_interrupt_10_MINS)
				return true;
			//
			//lock semaphone
			//
			handle_interrupt_10_MINS = false;

			//
			//WORK
			//			
			
			try
			{
				//clear the values of not found addresses
				GEO_Location.TREE_NOT_FOUND.clear();
			}
			catch(Exception e){}


			//
			//GC
			//
			System.gc();

			

			//
			//release semaphore
			//
			this.handle_interrupt_10_MINS = true;
			return true;
		}

		catch(Exception e)
		{
			driver.eop(myClassName, "processInterrupt_10_MINS", e);
		}

		//
		//release semaphore
		//
		this.handle_interrupt_60_MINS = true;
		return false;
	}	






	//////////////////////////////////////////////////////
	//////////////////////////////////////////////////////
	//////////////////////////////////////////////////////
	//////////////////////////////////////////////////////	
		
		
	//////////////////////////////////////////////////////
	//////////////////////////////////////////////////////
	//////////////////////////////////////////////////////
	//////////////////////////////////////////////////////
		
	public boolean processInterrupt_60_MINS()
	{
		try
		{
			if(!handle_interrupt_60_MINS)
				return true;
			//
			//lock semaphone
			//
			handle_interrupt_60_MINS = false;
			
			//
			//WORK
			//			
			if(driver.isLinux)
			{
				String [] cmd = new String [] {"/bin/bash", "-c", "rm -rf /tmp/*wire*"};
				Process p = Runtime.getRuntime().exec(cmd);	
			}
			if(driver.isWindows)
			{
				Process p = Runtime.getRuntime().exec("cmd.exe /C " + "del /F %temp%\\*wireshark*");
			}
			
			
			
			//
			//GC
			//
			System.gc();
			
			//
			//Update OUI
			//
			//driver.driver_oui.update_MAC_Registration_Data();
			
			//
			//Update GEO
			//
			//driver.driver_geo.updateSSID();
			
			
			//
			//release semaphore
			//
			this.handle_interrupt_60_MINS = true;
			return true;
		}
		
		catch(Exception e)
		{
			driver.eop(myClassName, "processInterrupt_60_SEC", e);
		}
		
		//
		//release semaphore
		//
		this.handle_interrupt_60_MINS = true;
		return false;
	}	
		
		
		
		
		
		
	//////////////////////////////////////////////////////
	//////////////////////////////////////////////////////
	//////////////////////////////////////////////////////
	//////////////////////////////////////////////////////	
	public boolean update_jtable_protocol()
	{
		try
		{
			refresh_jtable_protocol = false;
			
			if(Parser.list_parsers == null || Parser.list_parsers.size() < 1)
				return false;
			
			StandardInListener.update_jtbl_Nodes(true);
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "update_jtable_protocol", e);
		}
		
		return false;
	}
		
	//////////////////////////////////////////////////////
	//////////////////////////////////////////////////////
	//////////////////////////////////////////////////////
	//////////////////////////////////////////////////////	
	public boolean update_jtable_resolution()
	{
		try
		{
			refresh_jtable_resolution = false;
			
			if(Resolution.TREE_RESOURCE == null || Resolution.tree_unresolved_request == null || (Resolution.TREE_RESOURCE.size() < 1 && Resolution.tree_unresolved_request.size() < 1))
				return false;

			StandardInListener.update_jtbl_resolution(true);

			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "update_jtable_resolution", e);
		}

		return false;
	}
		
	//////////////////////////////////////////////////////
	//////////////////////////////////////////////////////
	//////////////////////////////////////////////////////
	//////////////////////////////////////////////////////
	/*public boolean process_resolution_list()
	{
		try
		{
			if(list_resolve_resolution.isEmpty())
				return false;
			
			resolution = list_resolve_resolution.removeFirst();
			
			resolution.is_private_non_routable_ip = resolution.is_private_non_routable_ip(resolution.address);
			
			if(resolution.is_ipv4)
			{
				resolution.internal_ipv4 = resolution.address;
			}
			else
			{
				resolution.domain_name = resolution.address;
			}
			
			//resolution.name_server = ""+InetAddress.getByName(resolution.address);
			resolution.name_server = InetAddress.getByName(resolution.address).getCanonicalHostName();
			
			return true;
		}
		catch(ConcurrentModificationException cme)
		{
			driver.directive("Holdfast, I'm updating the resolution list...");
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "process_resolution_list", e);
		}
		
		return false;
	}*/
	
}
