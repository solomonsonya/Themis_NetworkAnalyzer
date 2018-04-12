/**
 * Container for instance, right now, the OUI shows the company name, however there are many macs that all might resolve to the same Company name.
 * The purpose of this class is to have a unique company name that then stores a list of NODE_OUI's that have the list of devices linked to it 
 * @author Solomon Sonya
 */

package OUI_Parser;

import java.util.LinkedList;
import java.util.TreeMap;
import Profile.*;
import Driver.*;

public class Node_OUI_Container_GUI 
{
	public static final String myClassName = "Node_OUI_Container_GUI";
	public static volatile Driver driver = new Driver();

	public volatile static TreeMap<String, Node_OUI_Container_GUI> TREE_OUI_COMPANY_NAME = new TreeMap<String, Node_OUI_Container_GUI>();
	
	public volatile	LinkedList<Node_OUI> list_oui = new LinkedList<Node_OUI>();
	
	public volatile String COMPANY = "";
	
	public volatile String [] arr_jtable_row = null;
	
	public volatile int device_count = 0;
	public volatile String oui_listing = "";
	
	public volatile String value = "";
	public volatile String linked_devices = "";
	
	public static volatile int index = 0;
	public static volatile int val_count = 0;
	public static volatile String [] arrNames = null;
	public static volatile int [] arrValues = null;
	
	public Node_OUI_Container_GUI(String myCompanyName, Node_OUI oui)
	{
		try
		{
			COMPANY = myCompanyName;
			
			if(COMPANY != null)
			{
				COMPANY = COMPANY.trim();
				
				//
				//CHECK IF NAME ALREADY EXISTS
				//
				if(TREE_OUI_COMPANY_NAME.containsKey(COMPANY))
				{
					Node_OUI_Container_GUI container = TREE_OUI_COMPANY_NAME.get(COMPANY);
					
					if(container != null)
						container.link_oui(oui);
					else
					{
						TREE_OUI_COMPANY_NAME.put(COMPANY, this);
						this.link_oui(oui);
					}
				}
				
				//
				//NAME DOESN'T EXIST, ADD SELF TO IT!
				//
				else
				{
					TREE_OUI_COMPANY_NAME.put(COMPANY, this);
					this.link_oui(oui);
				}
						
			}
			
			
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "Constructor - 1", e);
		}
	}
	
	public boolean link_oui(Node_OUI oui)
	{
		try
		{
			if(!this.list_oui.contains(oui))
				this.list_oui.add(oui);
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "link_oui", e);
		}
		
		return false;
	}
	
	
	public String [] get_jtable_row()
	{
		try
		{
			if(arr_jtable_row == null)
				arr_jtable_row = new String[4];
			
			//COMPANY NAME
			arr_jtable_row[0] = this.COMPANY;
			
			//LINKED DEVICE TOTAL COUNT
			if(this.list_oui == null || this.list_oui.isEmpty())
				arr_jtable_row[1] = "0";
			else
			{
				device_count = 0;
				oui_listing = "Listing";
				
				for(Node_OUI node : this.list_oui)
				{
					if(node == null)
						continue;
					
					device_count += node.tree_Node_OUI.size();
					
					oui_listing = oui_listing + ", " + node.getMAC(":");  
				}
				
				arr_jtable_row[1] = "" + device_count;
			}
			
			//UNIQUE OUIs
			if(list_oui == null || list_oui.isEmpty())
				arr_jtable_row[2] = "0";
			else
				arr_jtable_row[2] = "" + this.list_oui.size();
			
			//OUI's
			arr_jtable_row[3] = oui_listing;
			
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "get_jtable_row", e);
		}
		
		return arr_jtable_row;
	}
	
	
	
	public String get_data_row_summary(String delimiter)
	{
		try
		{
			value = "Company Name:\n=============\n" + COMPANY + "\n\n";
			
			value = value + "Unique Device Identifiers:\n==========================\n";
			linked_devices = "";
			
			for(Node_OUI oui : this.list_oui)
			{
				if(oui == null)
					continue;
				
				value = value + oui.getMAC(":") + "\t" + "Country: " + oui.COUNTRY_CODE + "\t" + "Address: " + oui.ADDRESS + "\t" + oui.CITY_ZIP + "\n";
				
				linked_devices = linked_devices + "\n" + oui.get_linked_nodes("\n");
			}
			
			//linked nodes
			value = value + "\nLinked Nodes:\n=============" + linked_devices;
			
			return value;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "get_data_row_summary", e);
		}
		
		return " - No device data collected yet...";
	}
	
	
	
	
	public static boolean update_names_and_values()
	{
		try
		{
			if(TREE_OUI_COMPANY_NAME == null || TREE_OUI_COMPANY_NAME.isEmpty())
				return false;
			
			val_count = TREE_OUI_COMPANY_NAME.size();
			
			arrNames = new String[val_count];
			arrValues = new int[val_count];
			
			
			index = 0;
			for(Node_OUI_Container_GUI container : TREE_OUI_COMPANY_NAME.values())
			{
				if(index >= arrNames.length)
					break;
				
				if(container == null)
					continue;
				
				arrNames[index] = container.COMPANY;
				
				for(Node_OUI node : container.list_oui)
				{
					if(node == null)
						continue;
					
					arrValues[index] += node.tree_Node_OUI.size();
					
				}
						
				++index;
			}
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "update_names_and_values", e);
		}
		
		return false;
	}
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
}
