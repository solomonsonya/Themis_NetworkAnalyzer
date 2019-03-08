/**
 * NOTE: I am assuming the Organizationally Unique Identifier is truly UNIQUE and not handling duplicates
 * 
 * I have adapted this calss from the one I created in the Theia Project
 * 
 * @author Solomon Sonya
 */

package OUI_Parser;

import java.util.LinkedList;
import java.util.TreeMap;
import Profile.*;
import Driver.*;

public class Node_OUI 
{
	public volatile String value = null;
	public volatile String connected_devices_list = null;
	
	/**Populated in OUI_Parser*/
	public static volatile TreeMap<String, Node_OUI> tree_OUI_MAC  = new TreeMap<String, Node_OUI>();
	
	public static Driver driver = new Driver();
	public static final String not_specified = "not specified";
	public static final String myClassName = "Node_OUI";
	
	public volatile String MAC_STRIPPED = not_specified;
	public volatile String COMPANY = not_specified;
	public volatile String ADDRESS = not_specified;
	public volatile String CITY_ZIP = not_specified;
	public volatile String CITY = not_specified;
	public volatile String ZIP = not_specified;
	public volatile int zip = -1;
	public volatile String COUNTRY_CODE = not_specified;
	
	/**Stores the nodes that are actually in and captured by the system. String is MAC_STRIPPED*/
	public volatile static TreeMap<String, Node_OUI> tree_oui_in_use = new TreeMap<String, Node_OUI>();
		
	public static volatile Node_OUI oui = null;
	
	/**Stores a tree of all devices linked to it. String is SOURCE_MAC_ACCEPTED address*/
	public volatile TreeMap<String, SOURCE> tree_Node_OUI = new TreeMap<String, SOURCE>();
	
	public volatile static boolean updated_required = false;
	
	public volatile String [] arr_jtable_row = null;
	
	public Node_OUI(){}
	
	
	
	public String getMAC(String token)
	{
		try
		{			
			return (MAC_STRIPPED.substring(0,2) + token + MAC_STRIPPED.substring(2,4) + token + MAC_STRIPPED.substring(4));
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "getMAC", e, false);
		}
		
		return this.MAC_STRIPPED;
	}
	
	public String getData(String delimiter, String mac_splitter_token, boolean legacy_mode)
	{
		try
		{
			delimiter = delimiter + " " + "\t";//so that the split will at least have a value in between delimiters
			
			if(legacy_mode)
				return MAC_STRIPPED + delimiter + getMAC(mac_splitter_token) + delimiter + COMPANY + delimiter + ADDRESS + delimiter + CITY + delimiter + zip + delimiter + ZIP + delimiter + CITY_ZIP + delimiter + COUNTRY_CODE + " ";   
			
			return "mac_stripped: " + MAC_STRIPPED + delimiter + "mac: " + getMAC(mac_splitter_token) + delimiter + "company: " + COMPANY + delimiter + "address: " + ADDRESS + delimiter + "city: " + CITY + delimiter + "zip: " + zip + delimiter + "ZIP: " + ZIP + delimiter + "city_zip: " + CITY_ZIP + delimiter + "country_code: " + COUNTRY_CODE + " ";
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "getData", e);
		}
		
		return "invalid specification...";			
	}
	
	
	public static Node_OUI getMAC_OUI(String mac)
	{
		try
		{
			if(mac == null || mac.trim().equals(""))
				return null;
			
			mac = driver.strip_MAC(mac).toLowerCase();
			
			//get only first 6 bytes
			if(mac.length() > 6)
				mac = mac.substring(0,6);
			
			oui = Node_OUI.tree_OUI_MAC.get(mac);
			
			try
			{
				if(oui != null && !Node_OUI.tree_oui_in_use.containsKey(oui.MAC_STRIPPED))
					Node_OUI.tree_oui_in_use.put(oui.MAC_STRIPPED, oui);
			}
			catch(Exception e){}
			
			return oui;
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "getMAC_OUI", e);
		}
		
		return null;
	}
	
	public static String getMAC_OUI_Company_Name(String mac)
	{
		try
		{
			if(mac == null || mac.trim().equals(""))
				return null;
			
			mac = driver.strip_MAC(mac).toLowerCase();
			
			//get only first 6 bytes
			if(mac.length() > 6)
				mac = mac.substring(0,6);
			
			oui = Node_OUI.tree_OUI_MAC.get(mac);
			
			if(oui == null)
				return "";
			
			try
			{
				if(oui != null && !Node_OUI.tree_oui_in_use.containsKey(oui.COMPANY.trim()))
					Node_OUI.tree_oui_in_use.put(oui.COMPANY.trim(), oui);
			}
			catch(Exception e){}
			
			return oui.COMPANY;
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "getMAC_OUI_Company_Name", e);
		}
		
		return "";
	}
	
	public String get_data_row_summary(String delimiter)
	{
		try
		{
			value = "MAC Address:\n============\n" + this.getMAC(":") + "\n\n";
			value = value + "Vendor Name:\n============\n" + this.COMPANY + "\n\n";
			value = value + "Address:\n========\n" + this.ADDRESS + "\n\n";
			value = value + "City, State:\n===========\n" + this.CITY_ZIP + "\n\n";
			value = value + "Zip:\n====\n" + this.ZIP + "\n\n";
			value = value + "Country Code:\n============\n" + this.COUNTRY_CODE + "\n\n";
			
			value = value + "Detected Nodes:\n===============\n" + this.get_linked_nodes("\n");
			
			return value;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "get_data_row_summary");
		}
		
		return "Company name --> " + this.COMPANY;
	}
	
	public String get_linked_nodes(String delimiter)
	{
		try
		{
			if(this.tree_Node_OUI == null || this.tree_Node_OUI.isEmpty())
				return "- No detected devices linked yet...";
			
			this.connected_devices_list = "";
			
			LinkedList<SOURCE> list = new LinkedList<SOURCE>(this.tree_Node_OUI.values());
			
			if(list == null || list.isEmpty())
				return "- - No detected devices linked yet...";
			
			SOURCE source = list.getFirst();
			
			if(source != null)
				connected_devices_list = source.src_ip + "\t" + source.src_mac + "\t" + this.COMPANY;
			
			for(int i = 1; i < list.size(); i++)
			{
				if(source == null)
					continue;
				
				connected_devices_list = connected_devices_list + delimiter + source.src_ip + "\t" + source.src_mac + "\t" + this.COMPANY;
			}
			
			return connected_devices_list;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "get_linked_nodes", e);
		}
		
		return "- - - - No Devices linked yet...";
	}
	
	public boolean link_device(SOURCE node)
	{
		try
		{
			if(node == null)
				return false;
			
			if(!this.tree_Node_OUI.containsKey(node.src_mac))
				tree_Node_OUI.put(node.src_mac, node);
			
			
			
			if(Node_OUI_Container_GUI.TREE_OUI_COMPANY_NAME.containsKey(COMPANY))
			{
				Node_OUI_Container_GUI container = Node_OUI_Container_GUI.TREE_OUI_COMPANY_NAME.get(COMPANY);
				
				if(container != null)
				{
					container.link_oui(this);
				}
				else
				{
					//container was null
					Node_OUI_Container_GUI contner = new Node_OUI_Container_GUI(COMPANY, this);//linking id done automagically
				}
			}
			else
			{
				//container was null
				Node_OUI_Container_GUI contner = new Node_OUI_Container_GUI(COMPANY, this);//linking id done automagically
			}
			
			this.updated_required = true;
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "link_device", e);
		}
		
		return false;
	}
	
	
	public String [] get_jtable_row()
	{
		try
		{
			if(arr_jtable_row == null)
				arr_jtable_row = new String[3];
			
			arr_jtable_row[0] = this.getMAC(":");
			arr_jtable_row[1] = this.COMPANY;
			
			if(this.tree_Node_OUI == null || this.tree_Node_OUI.isEmpty())
				arr_jtable_row[2] = "0";
			else
				arr_jtable_row[2] = "" + this.tree_Node_OUI.size();
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "get_jtable_row", e);
		}
		
		return arr_jtable_row;
	}
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
}
