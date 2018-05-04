/**
 * Working on Cross-Compatibility between different projects. 
 * 
 * Here, let's create a node that stores the Lat, Lon, and Map details for what ever node. 
 * 
 * Then we can create a list of these objects to be displayed on the Map
 * 
 * @Solomon Sonya
 */

package Map;

import Driver.*;

public class Node_Map_Details 
{
	public static final String myClassName = "Node_Map_Details";
	public static volatile Driver driver = new Driver();

	public volatile double latitude = 0.0;
	public volatile double longitude = 0.0;
	public volatile String details = "";
	
	public Node_Map_Details(String lat, String lon, String map_details)
	{
		try
		{
			try	{	latitude  = Double.parseDouble(lat.trim());	}	catch(Exception e){latitude  = 0.0;}
			try	{	longitude = Double.parseDouble(lon.trim());	}	catch(Exception e){longitude = 0.0;}
			
			details = map_details;			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "Constructor - 1", e);
		}
	}
}
