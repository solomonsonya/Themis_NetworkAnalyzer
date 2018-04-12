/**
 * Special thanks to freegeoip.net
 * 
 * @author Solomon Sonya
 */

package GEO_Location;

import java.io.*;
import java.net.*;
import java.util.*;
import Driver.*;
import Profile.*;

public class GEO_Location extends Thread implements Runnable
{	
	
	public static volatile boolean GEO_RESOLUTION_ENABLED = false;
	public static final String myClassName = "GEO_Location";
	public static volatile Driver driver = new Driver();
	
	public static volatile Log log_geo = null;
	public static volatile Log log_not_found = null;
	
	/**Just to indicate addresses we've started to lookup*/
	public static volatile TreeMap<String, String> TREE_ADDRESS_TO_LOOKUP = new TreeMap<String, String>();
	
	public static volatile TreeMap<String, GEO_Location> TREE_GEO_LOCATION = new TreeMap<String, GEO_Location>();
	
	public static volatile TreeMap<String, GEO_Location> TREE_NOT_FOUND = new TreeMap<String, GEO_Location>();
	
	public static final String QUERY_ADDRESS = "http://freegeoip.net/json/";
			
	public static volatile String origin_latitude = "0";
	public static volatile String origin_longitude = "0";
	
	public String address = "";
	
	public volatile String ip = "";
	public volatile String country_code = "";
	public volatile String country_name = "";
	public volatile String region_code = "";
	public volatile String region_name = "";
	public volatile String city = "";
	public volatile String zip_code = "";
	public volatile String time_zone = "";
	public volatile String latitude = "";
	public volatile String longitude = "";
	public volatile String metro_code = "";
	
	public volatile String geo_string = "";
	
	public GEO_Location(String addr)
	{
		try
		{						
			if(addr != null && !addr.trim().equals(""))
			{
				addr = addr.toLowerCase().trim();
				address = addr;
				
				if(TREE_ADDRESS_TO_LOOKUP.containsKey(addr))
				{
					//do n/t since we've already tried to resolve the address
					TREE_ADDRESS_TO_LOOKUP.put(addr,  null);
				}
				else if(TREE_GEO_LOCATION.containsKey(addr))
				{
					//do nothing, address was found!					
				}
				else if(TREE_NOT_FOUND.containsKey(addr))//this is routinely cleared in thdworker
				{
					//again, do nothing since we've tried before, and the address was not found, or timed out before we could get a request					
				}
				else if(is_private_non_routable_ip(addr))
				{
					//once more, do nothing on private ip addresses
				}
				else
				{
					//attempt to resolve!
					if(GEO_RESOLUTION_ENABLED)
						this.start();
				}
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
			//good reference: https://stackoverflow.com/questions/2793150/how-to-use-java-net-urlconnection-to-fire-and-handle-http-requests, https://stackoverflow.com/questions/3163693/java-urlconnection-timeout
			
			//address was not found, attempt to resolve now!
			driver.sop("Attempting to resolve GEO for: " + address);
			
			URL url = new URL(QUERY_ADDRESS + address);
			HttpURLConnection connection = (HttpURLConnection) url.openConnection();
			HttpURLConnection.setFollowRedirects(true);
			connection.setConnectTimeout(20 * 1000);
			connection.setRequestMethod("GET");
			connection.setRequestProperty("User-Agent", "Mozilla/5.0 (Windows; U; Windows NT 6.0; en-US; rv:1.9.1.2) Gecko/20180719 chrome/64.0.3282.140 (.NET CLR 3.5.30729)");
			connection.connect();
			
			BufferedReader brIn = new BufferedReader(new InputStreamReader(connection.getInputStream()));
			
			String line = "";
			
			while((line = brIn.readLine()) != null)
			{
				line = line.trim();
				
				if(line.trim().equals(""))
					continue;
				
				process_line(line);
			}
			
			try	{	brIn.close();} catch(Exception e){}
			
			
			System.gc();
		}
		
		
		catch(FileNotFoundException fnef)
		{
			TREE_NOT_FOUND.put(address, null);
			driver.sop("GEO Resolution for Address [" + address + "] was not found...");
		}
		catch(IOException ioe)
		{
			//bad request 400
			TREE_NOT_FOUND.put(address, null);
		}
		catch(Exception e)
		{
			TREE_NOT_FOUND.put(address, null);
			
			driver.eop(myClassName, "run", e);
		}
	}
	
	
	public boolean process_line(String line)
	{
		try
		{
			if(line == null)
				return false;
			
			line = line.replaceAll("\"", "").trim();
			
			if(line.equals(""))
				return false;
			
			line = line.replaceAll("\\{", "");
			line = line.replaceAll("\\}", "");
			
			String [] array = line.split(",");
			
			if(array == null || array.length < 1)
				return false;
			
			String lower = "";
			for(String tuple : array)
			{
				tuple = tuple.trim();
				
				if(tuple.equals(""))
					continue;
				
				lower = tuple.toLowerCase().trim();
				
				if(lower.startsWith("ip"))
					this.ip = tuple.substring(3).trim();
				else if(lower.startsWith("country_code"))
					this.country_code = tuple.substring(13).trim();
				else if(lower.startsWith("country_name"))
					this.country_name = tuple.substring(13).trim();
				else if(lower.startsWith("region_code"))
					this.region_code = tuple.substring(12).trim();
				else if(lower.startsWith("region_name"))
					this.region_name = tuple.substring(12).trim();
				else if(lower.startsWith("city"))
					this.city = tuple.substring(5).trim();
				else if(lower.startsWith("zip_code"))
					this.zip_code = tuple.substring(9).trim();
				else if(lower.startsWith("time_zone"))
					this.time_zone = tuple.substring(10).trim();
				else if(lower.startsWith("latitude"))
					this.latitude = tuple.substring(9).trim();
				else if(lower.startsWith("longitude"))
					this.longitude = tuple.substring(10).trim();
				else if(lower.startsWith("metro_code"))
					this.metro_code = tuple.substring(11).trim();				
				
			}
			
			
			
			//ip:23.52.32.93,country_code:NL,country_name:Netherlands,region_code:NH,region_name:North Holland,city:Amsterdam,zip_code:1091,time_zone:Europe/Amsterdam,latitude:52.35,longitude:4.9167,metro_code:0

			/*driver.directive("ip-->" + ip + "<--");
			driver.directive("country_code-->" + country_code + "<--");
			driver.directive("country_name-->" + country_name + "<--");
			driver.directive("region_code-->" +region_code  + "<--");
			driver.directive("region_name-->" +  region_name+ "<--");
			driver.directive("city-->" + city + "<--");
			driver.directive("zip_code-->" + zip_code + "<--");
			driver.directive("time_zone-->" + time_zone + "<--");
			driver.directive("latitude-->" + latitude + "<--");
			driver.directive("longitude-->" + longitude + "<--");
			driver.directive("metro_code-->" + metro_code + "<--");*/
			
			//here, validate lat and lon, if so, store
			try
			{
				Double.parseDouble(this.latitude);
				Double.parseDouble(this.longitude);
				
				if(!TREE_GEO_LOCATION.containsKey(address))
				{
					TREE_GEO_LOCATION.put(address,  this);					
					log_geo(", ");
				}
				
				//add self to the resource
				if(SOURCE.TREE_SOURCE_NODES.containsKey(address))
				{
					SOURCE src = SOURCE.TREE_SOURCE_NODES.get(address);
					
					if(src != null)
						src.geo = this;
				}
				
				if(Resolution.TREE_RESOURCE.containsKey(address))
				{
					Resolution resource = Resolution.TREE_RESOURCE.get(address);
					
					if(resource != null)
						resource.geo = this;
				}
			}
			catch(Exception e)
			{
				TREE_NOT_FOUND.put(address,  this);
				log_not_found(address);
			}
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "process_line", e);
		}
		
		return false;
	}
	
	
	public boolean log_geo(String delimiter)
	{
		try
		{
			//
			//log dns resolution
			//
			if(this.log_geo == null)
			{
				log_geo = new Log("geo/geo_found/",  "geo_found", 250, 999999999);
				log_geo.OVERRIDE_LOGGING_ENABLED = true;
			}
			
			log_geo.log_directly(
									"ip: " + ip + delimiter + 
									"country_code: " + country_code + delimiter + 
									"country_name: "  + country_name + delimiter + 
									"region_code: "  + region_code + delimiter + 
									"region_name: "  + region_name + delimiter + 
									"city: "  + city + delimiter + 
									"zip_code: "  + zip_code + delimiter + 
									"time_zone: "  + time_zone + delimiter + 
									"latitude: "  + latitude + delimiter + 
									"longitude: "  + longitude + delimiter + 
									"metro_code: "  + metro_code);
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "log_geo", e);
		}
		
		return false;
	}
	
	public String get_data(String delimiter)
	{
		try
		{
			
							return	"ip: " + ip + delimiter + 
									"country_code: " + country_code + delimiter + 
									"country_name: "  + country_name + delimiter + 
									"region_code: "  + region_code + delimiter + 
									"region_name: "  + region_name + delimiter + 
									"city: "  + city + delimiter + 
									"zip_code: "  + zip_code + delimiter + 
									"time_zone: "  + time_zone + delimiter + 
									"latitude: "  + latitude + delimiter + 
									"longitude: "  + longitude + delimiter + 
									"metro_code: "  + metro_code;
			
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "get_data", e);
		}
		
		return " ++ ";
	}
	
	public String toString(String delimiter)
	{
		try
		{
			delimiter = delimiter + " ";
			
			geo_string = "";
			
			if(ip != null && !ip.trim().equals(""))
				geo_string = " geo_ip: " + ip + delimiter;
			
			if(country_code != null && !country_code.trim().equals(""))
				geo_string = geo_string +  "geo_country_code: " + country_code + delimiter ;
			
			if(country_name != null && !country_name.trim().equals(""))
				geo_string = geo_string +  "geo_country_name: "  + country_name + delimiter ; 
			
			if(region_code != null && !region_code.trim().equals(""))
				geo_string = geo_string +  "geo_region_code: "  + region_code + delimiter ; 
			
			if(region_name != null && !region_name.trim().equals(""))
				geo_string = geo_string +  "geo_region_name: "  + region_name + delimiter ;
			
			if(city != null && !city.trim().equals(""))
				geo_string = geo_string +  "geo_city: "  + city + delimiter ; 
			
			if(zip_code != null && !zip_code.trim().equals(""))
				geo_string = geo_string +  "geo_zip_code: "  + zip_code + delimiter ; 
			
			if(time_zone != null && !time_zone.trim().equals(""))
				geo_string = geo_string +  "geo_time_zone: "  + time_zone + delimiter ; 
			
			if(latitude != null && !latitude.trim().equals(""))
				geo_string = geo_string +  "geo_latitude: "  + latitude + delimiter ; 
			
			if(longitude != null && !longitude.trim().equals(""))
				geo_string = geo_string +  "geo_longitude: "  + longitude + delimiter ;
			
			if(metro_code != null && !metro_code.trim().equals(""))
				geo_string = geo_string +  "geo_metro_code: "  + metro_code;
			
			
			return geo_string;
			
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "toString", e);
		}
		
		return " ++ ";
	}
	
	public boolean log_not_found(String address)
	{
		try
		{
			//
			//log dns resolution
			//
			if(this.log_not_found == null)
			{
				log_not_found = new Log("geo/geo_not_found/",  "geo_not_found", 250, 999999999);
				log_not_found.OVERRIDE_LOGGING_ENABLED = true;
			}
			
			log_not_found.log_directly(address);
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "log_not_found", e);
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
	
	
	public void resolve_self()
	{
		try
		{
			//good reference: https://stackoverflow.com/questions/2793150/how-to-use-java-net-urlconnection-to-fire-and-handle-http-requests, https://stackoverflow.com/questions/3163693/java-urlconnection-timeout
			
			//address was not found, attempt to resolve now!
			driver.sop("Attempting to resolve external GEO information...");
			
			URL url = new URL(QUERY_ADDRESS + address);
			address = "me";
			HttpURLConnection connection = (HttpURLConnection) url.openConnection();
			HttpURLConnection.setFollowRedirects(true);
			connection.setConnectTimeout(20 * 1000);
			connection.setRequestMethod("GET");
			connection.setRequestProperty("User-Agent", "Mozilla/5.0 (Windows; U; Windows NT 6.0; en-US; rv:1.9.1.2) Gecko/20180719 chrome/64.0.3282.140 (.NET CLR 3.5.30729)");
			connection.connect();
			
			BufferedReader brIn = new BufferedReader(new InputStreamReader(connection.getInputStream()));
			
			String line = "";
			
			while((line = brIn.readLine()) != null)
			{
				line = line.trim();
				
				if(line.trim().equals(""))
					continue;
				
				process_line(line);
			}
			
			try	{	brIn.close();} catch(Exception e){}
			
			driver.directive("If successful, our Geo information was found to be: " + get_data(", "));
			
			origin_latitude = latitude;
			origin_longitude = longitude;
									
			System.gc();
		}
		
		
		catch(FileNotFoundException fnef)
		{
			driver.directive("\nNOTE! I CAN NOT RESOLVE OUR EXTERNAL IP");							
		}
		catch(Exception e)
		{						
			driver.eop(myClassName, "resolve_self", e);
		}
	}
	
	
	
	
}
