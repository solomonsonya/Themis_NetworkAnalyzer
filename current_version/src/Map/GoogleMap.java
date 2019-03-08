package Map;
import java.io.*;
import java.text.SimpleDateFormat;
import java.util.*;
import Driver.*;
import GEO_Location.GEO_Location;


public class GoogleMap 
{
	public static final String myClassName = "GoogleMap";
	public static volatile Driver driver = new Driver();
	
	File fleMapTopFolder = new File("." + File.separator + Driver.NAME + File.separator + "map" + File.separator);
	String pathToTopFolder = "";
	public File fleMap = null;
	PrintWriter pwOut = null;
	volatile String client_count = "Client Count: [0]";
		
	public static final int MAX_NODE_OUTPUT = -1;
	public static int CURR_NODE_OUTPUT = 0;
	
	public volatile Date date = new Date(System.currentTimeMillis());
	public volatile SimpleDateFormat dateFormat = new SimpleDateFormat("dd:HH:mm:ss");
	public volatile SimpleDateFormat dateFormat_yyyy_mm_dd_hh_mm_ss = new SimpleDateFormat("yyyy-MM-dd-HHmm:ss");
	public volatile Date dateTime_yyyy_mm_dd_hh_mm_ss = new Date(System.currentTimeMillis());
	
	String TITLE = "", MAP_NAME_WITH_EXTENSION = "";
	boolean OPEN_UPON_COMPLETION = false;
	
	public static long refresh_seconds = 600;
		
	public volatile LinkedList<Node_Map_Details> list_map_details = new LinkedList<Node_Map_Details>();
	public volatile GEO_Location geo_center = null;
	
	/**
	 * Single markers on google map. non-connected lines
	 * @param title
	 * @param map_name_with_extension
	 * @param list_details
	 * @param open_upon_completion
	 * @param verbose
	 * @param refresh_seconds_ok_to_be_negative
	 */
	public GoogleMap(String title, String map_name_with_extension, LinkedList<Node_Map_Details> list_details, boolean open_upon_completion, boolean verbose, int refresh_seconds_ok_to_be_negative)
	{
		try
		{
			//determine self location
			if(Driver.GEO_LOCATION_ME == null)
				Driver.GEO_LOCATION_ME = new GEO_Location();
			
			TITLE = title;
			MAP_NAME_WITH_EXTENSION = map_name_with_extension;
			list_map_details = list_details;
			OPEN_UPON_COMPLETION = open_upon_completion;
			
			refresh_seconds = refresh_seconds_ok_to_be_negative;
			
			if(list_details != null && list_details.size() > 0)
				this.draw_map(title, map_name_with_extension, list_map_details, open_upon_completion, verbose);
			
		}
		catch(Exception e)
		{
			
		}
	}
	
	/**
	 * Markers on the map, connected to location at geo_center
	 * @param geo_center
	 * @param title
	 * @param map_name_with_extension
	 * @param list_details
	 * @param open_upon_completion
	 * @param verbose
	 * @param refresh_seconds_ok_to_be_negative
	 */
	public GoogleMap(GEO_Location geo, String title, String map_name_with_extension, LinkedList<Node_Map_Details> list_details, boolean open_upon_completion, boolean verbose, int refresh_seconds_ok_to_be_negative)
	{
		try
		{
			geo_center = geo;
			
			//determine self location
			if(Driver.GEO_LOCATION_ME == null)
				Driver.GEO_LOCATION_ME = new GEO_Location();
			
			TITLE = title;
			MAP_NAME_WITH_EXTENSION = map_name_with_extension;
			list_map_details = list_details;
			OPEN_UPON_COMPLETION = open_upon_completion;
			
			refresh_seconds = refresh_seconds_ok_to_be_negative;
			
			if(list_details != null && list_details.size() > 0)
				this.draw_map_connected_lines(geo, title, map_name_with_extension, list_map_details, open_upon_completion, verbose);
			
		}
		catch(Exception e)
		{
			
		}
	}
	
	/**
	 * This is the newer google mapping function
	 * @param title
	 * @param include_client_devices
	 * @return
	 */
	public boolean draw_map(String title, String map_name_with_extension, LinkedList<Node_Map_Details> list_details, boolean open_upon_completion, boolean verbose)
	{
		try
		{
			
			if(list_details == null || list_details.size() < 1)
				return false;
			
			//create file
			if(!fleMapTopFolder.exists() || !fleMapTopFolder.isDirectory())
			{
				fleMapTopFolder.mkdirs();		
				driver.directive("Map output top directory set to " + fleMapTopFolder.getCanonicalPath());
			}
						
			if(!fleMapTopFolder.exists() || !fleMapTopFolder.isDirectory())
				throw new Exception("Unable to create required directories at: " + "./");
			
			pathToTopFolder = fleMapTopFolder.getCanonicalPath().trim();
			
			if(!pathToTopFolder.endsWith(File.separator))
				pathToTopFolder = pathToTopFolder + File.separator;
			
			if(map_name_with_extension == null || map_name_with_extension.trim().equals(""))
				map_name_with_extension = "map_" + System.currentTimeMillis() + ".html";
			
			if(fleMap == null)
			{
				fleMap = new File(pathToTopFolder + map_name_with_extension);
				pwOut = new PrintWriter(new FileWriter(fleMap));
			}
			
			if(!fleMap.exists() || !fleMap.isFile())
				pwOut = new PrintWriter(new FileWriter(fleMap));
			
			//test if the writer is open and ok, if it throws an error, create a new file and writer
			try
			{
				pwOut.print("");
				pwOut.flush();
			}
			catch(Exception e)
			{
				//threw an error above, create a new file and print writer!
				map_name_with_extension = "map_" + System.currentTimeMillis() + ".html";
				fleMap = new File(pathToTopFolder + map_name_with_extension);
				pwOut = new PrintWriter(new FileWriter(fleMap));
			}
				
			
			client_count = "Client Count: [" + list_details.size() + "]";
			
			//special thanks to attila marosi!
			pwOut.println("<!DOCTYPE html>");
			pwOut.println("<html>");
			pwOut.println("  <head>");
			
			if(refresh_seconds > 0)
				pwOut.println("	<title>" + title + "</title>" + "<meta http-equiv=\"refresh\" content=\"" + this.refresh_seconds + "\">");
			else
				pwOut.println("	<title>" + title + "</title>");
			
			
			pwOut.println("		 <body bgcolor=\"white\"> <font color=\"blue\"> ");
			pwOut.println("		<h1>" + title + "</h1></font><hr>");
			pwOut.println("		<h2>" + client_count + "</h2>");
			pwOut.println("		<hr>");
			pwOut.println("");
			pwOut.println("    <meta name=\"viewport\" content=\"initial-scale=1.0, user-scalable=no\">");
			pwOut.println("    <meta charset=\"utf-8\">");
			pwOut.println("");
			pwOut.println("    <title>Map of your devices</title>");
			pwOut.println("    <style>");
			pwOut.println("      html, body {");
			pwOut.println("        height: 100%;");
			pwOut.println("        margin: 0;");
			pwOut.println("        padding: 0;");
			pwOut.println("      }");
			pwOut.println("      #map {");
			pwOut.println("        height: 100%;");
			pwOut.println("      }");
			pwOut.println("    </style>");
			pwOut.println("");
			pwOut.println("    <script src=\"http://ajax.googleapis.com/ajax/libs/jquery/1.7.2/jquery.min.js\"></script>");
			pwOut.println("  </head>");
			pwOut.println("  <body>");
			pwOut.println("    <div id=\"map\" ></div>");
			pwOut.println("");
			pwOut.println("    <script>");
			pwOut.println("");
			pwOut.println("    function DrawDevices(map)");
			pwOut.println("    { ");
			pwOut.println("      $.ajax({");
			pwOut.println("              url: \"/api/get_cordinates\",");
			pwOut.println("              type: \"GET\",");
			pwOut.println("              datatype:\"json\",");
			pwOut.println("              success: function(response){");
			pwOut.println("                  //process response to object");
			pwOut.println("                  response = $.parseJSON(response);");
			pwOut.println("");
			pwOut.println("                  if(response.result == true)");
			pwOut.println("                  {");
			pwOut.println("                      data = response.data;");
			pwOut.println("                      for (var i = data.length - 1; i >= 0; i--)");
			pwOut.println("                      {");
			pwOut.println("                        var location = {lat:data[i].location.latitude, lng:data[i].location.longitude};");
			pwOut.println("                        plotMarker(map, location, data[i]);");
			pwOut.println("                      }");
			pwOut.println("                  }");
			pwOut.println("                  else");
			pwOut.println("                  {");
			pwOut.println("                      console.log(\"Sad panda :(\");");
			pwOut.println("                  }");
			pwOut.println("          }");
			pwOut.println("      });");
			pwOut.println("    }");
			pwOut.println("");
			pwOut.println("//create info box markers");
			pwOut.println("    function plotMarker(map, location, device)");
			pwOut.println("    {");
			pwOut.println("        //FORMATTING");
			pwOut.println("		info_data = \"\";");
			pwOut.println("        info_data += \"<h4>\" + device.ID + \"</h4>\";");
			pwOut.println("        //info_data += \"Device: <b>\" + device.data + \"</b><br/>\";");
			pwOut.println("		info_data += \"\" + device.data + \"<br/>\";");
			pwOut.println("        var coordinate = new google.maps.LatLng(location.lat, location.lng);");
			pwOut.println("        var myinfowindow = new google.maps.InfoWindow(");
			pwOut.println("          {content: info_data}");
			pwOut.println("        );");
			pwOut.println("");
			pwOut.println("        // Create the marker");
			pwOut.println("        var marker = new google.maps.Marker({");
			pwOut.println("            map: map,");
			pwOut.println("            position: coordinate,");
			pwOut.println("            infowindow : myinfowindow");
			pwOut.println("        });");
			pwOut.println("");
			pwOut.println("        // Create Info window ");
			pwOut.println("        google.maps.event.addListener(marker, \"click\", function() {");
			pwOut.println("            this.infowindow.open(map, this);");
			pwOut.println("        });");
			pwOut.println("");
			pwOut.println("        google.maps.event.addListener(map, 'click', function() {");
			pwOut.println("            infowindow.close();");
			pwOut.println("        });");
			pwOut.println("    }");
			pwOut.println("");
			pwOut.println("    function initMap() {");
			pwOut.println("var map = new google.maps.Map(document.getElementById('map'), {");
			pwOut.println("    		zoom: 2,");
			pwOut.println("    		center: {lat: 51, lng: 3.7}");
			pwOut.println("    	});");
			
			
			//
			//NODE DEVICES
			//
			CURR_NODE_OUTPUT = 0;
			WRITE_NODE_DEVICE_INFORMATION(list_details, pwOut);					
			
			//
			//CONTINUE
			//
			pwOut.println("    }");
			pwOut.println("    </script>");
			pwOut.println("");
			pwOut.println("	<!-- this loads google Map API -->");
			pwOut.println("	<!-- please generate a personal API key for yourself here: -->");
			pwOut.println(" <!-- https://console.developers.google.com/apis/ -->");
			pwOut.println("    <script async defer");
			pwOut.println("        src=\"https://maps.googleapis.com/maps/api/js?key=AIzaSyBpjKTI6j_EZRjVUiFFBbBsfZjzEI6WchA&signed_in=true&callback=initMap\"></script>");
			pwOut.println("  </body>");
			pwOut.println("  <br><pre>" + Driver.FULL_NAME + " - Map vrs 0.200  by Solomon Sonya and Suhail Mushtaq     Map Update Time: " + getTime_Specified_Hyphenated_with_seconds(-1) + "</pre>");
			pwOut.println("</html>");
			
			pwOut.flush();
			pwOut.close();
			
			if(verbose)
				driver.directive("Process COMPLETE.  Barring errors, file written to: " + fleMap.getCanonicalPath());
			
			if(open_upon_completion)
			{
				driver.directive(map_name_with_extension + " has been exported to " + fleMap.getCanonicalPath());
				
				if(Driver.isWindows)
					try	{	Process p = Runtime.getRuntime().exec("explorer.exe " + fleMap.getCanonicalPath());	}	catch(Exception e){}
			}
			
			return true;
		}
		
		catch(FileNotFoundException fnfe)
		{
			driver.directive("* Hmm... I'm working on drawing map at location : " + fleMap);
		}
		
		catch(Exception e)
		{
			driver.eop(myClassName, "draw_map", e);
		}
		
		return false;
	}
	
	public boolean WRITE_NODE_DEVICE_INFORMATION(LinkedList<Node_Map_Details> list, PrintWriter pw)
	{
		try
		{
			if(list == null || list.isEmpty())
				return false;
			
			for(Node_Map_Details node : list)
			{
				try
				{
					if(MAX_NODE_OUTPUT > 0 && CURR_NODE_OUTPUT++ >= MAX_NODE_OUTPUT)
					{
						driver.directive("Max limit reached for writing devices to the map. Punting early...");
						return true;
					}					
					  
					if(node == null || (node.latitude == 0.0 && node.longitude == 0.0))
						continue;
					
					pwOut.println(node.details);					
				}
				catch(Exception e)
				{
					driver.eop_loop(myClassName, "WRITE_NODE_DEVICE_INFORMATION", e,-1);
					continue;
				}
			}
			
			
			//System.gc();
			return true;
		}
		catch(ConcurrentModificationException cme)
		{
			driver.directive("* * Halting write process prematurely. I am currently writting into the tree that you are attempting to access. I will however, provide data I have at the moment...");
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "WRITE_NODE_DEVICE_INFORMATION - list", e);
		}
		
		return false;
	}
	
	public  String getTime_Specified_Hyphenated_with_seconds(long time_millis)
	{
		try
		{			
			if(time_millis < 1000)
				time_millis = System.currentTimeMillis();
			
			dateTime_yyyy_mm_dd_hh_mm_ss.setTime(time_millis);			
			return dateFormat_yyyy_mm_dd_hh_mm_ss.format(dateTime_yyyy_mm_dd_hh_mm_ss);
		}
		catch(Exception e)
		{
			driver.sop("Invalid date specified -##-" + " it does not a proper date was selected");
			//Drivers.eop("Drivers", "getTime_Specified_Millis", "", e, false);
		}
		
		return "";
	}
	
	
	
	
	public boolean draw_map_connected_lines(GEO_Location geo, String title, String map_name_with_extension, LinkedList<Node_Map_Details> list_details, boolean open_upon_completion, boolean verbose)
	{
		try
		{
			if(list_details == null || list_details.size() < 1)
				return false;
			
			if(geo == null)
				return false;
			
			//create file
			if(!fleMapTopFolder.exists() || !fleMapTopFolder.isDirectory())
			{
				fleMapTopFolder.mkdirs();		
				driver.directive("Map output top directory set to " + fleMapTopFolder.getCanonicalPath());
			}
						
			if(!fleMapTopFolder.exists() || !fleMapTopFolder.isDirectory())
				throw new Exception("Unable to create required directories at: " + "./");
			
			pathToTopFolder = fleMapTopFolder.getCanonicalPath().trim();
			
			if(!pathToTopFolder.endsWith(File.separator))
				pathToTopFolder = pathToTopFolder + File.separator;
			
			if(map_name_with_extension == null || map_name_with_extension.trim().equals(""))
				map_name_with_extension = "map_" + System.currentTimeMillis() + ".html";
			
			if(fleMap == null)
			{
				fleMap = new File(pathToTopFolder + map_name_with_extension);
				pwOut = new PrintWriter(new FileWriter(fleMap));
			}
			
			if(!fleMap.exists() || !fleMap.isFile())
				pwOut = new PrintWriter(new FileWriter(fleMap));
			
			//test if the writer is open and ok, if it throws an error, create a new file and writer
			try
			{
				pwOut.print("");
				pwOut.flush();
			}
			catch(Exception e)
			{
				//threw an error above, create a new file and print writer!
				map_name_with_extension = "map_" + System.currentTimeMillis() + ".html";
				fleMap = new File(pathToTopFolder + map_name_with_extension);
				pwOut = new PrintWriter(new FileWriter(fleMap));
			}
				
			
			client_count = "Client Count: [" + list_details.size() + "]";
			
			pwOut.println("<!DOCTYPE html>");
			
			
			if(refresh_seconds > 0)
				pwOut.println("	<html>  <head>    <meta name=\"viewport\" content=\"initial-scale=1.0, user-scalable=no\">    <meta charset=\"utf-8\">    <meta http-equiv=\"refresh\" content=\"" + this.refresh_seconds + "\">");
			else
				pwOut.println("	<html>  <head>    <meta name=\"viewport\" content=\"initial-scale=1.0, user-scalable=no\">    <meta charset=\"utf-8\">    <meta http-equiv=\"refresh\" content=\"9999\">");
			
			//title
			pwOut.println("	    <title>" + title + "</title>    <style>");
			
			pwOut.println("	    #map {        height: 100%;      }");
			pwOut.println("	    html, body {        height: 100%;        margin: 0;        padding: 0;      }");
			
			pwOut.println("	</style>  </head>  <body>    <div id=\"map\"></div>    <script>");
			
			pwOut.println("function initMap() 	  {        var map = new google.maps.Map(document.getElementById('map'), 		{          zoom: 3,          center: {lat: " + geo.latitude + ", lng: " + geo.longitude + "}, mapTypeId: google.maps.MapTypeId.ROADMAP });");
			
			pwOut.println("var userCoor = [");
			
			pwOut.println("  [\"<b><u>ME!</b></u><br><br><b>Address: </b>" + geo.ip + "<br><b>Country Code:</b>" + geo.country_code + "<br><b>Country Name:</b>" + geo.country_name + "<br><b>State:</b> " + geo.region_name + "<br><b>Region Code:</b> " + geo.region_code + "<br><b>City:</b> " + geo.city + "<br><b>Zip Code:</b> " + geo.zip_code + "<br><b>Time Zone:</b> " + geo.time_zone + "<br><b>Latitude:</b> " + geo.latitude + "<br><b>Longitude:</b> " + geo.longitude + "<br>\"," + geo.latitude + ", " + geo.longitude + "],");
			
			for(Node_Map_Details element : list_details)
			{
				if(element == null )
					continue;
				
				pwOut.println("    [\"" + element.details.replaceAll("'", "") + "\", " + element.latitude + ", " + element.longitude + "],");
			}
			
			pwOut.println("];");
			pwOut.println("var userCoorPath = [");
			
			for(Node_Map_Details element : list_details)
			{
				if(element == null )
					continue;
				
				pwOut.println("    new google.maps.LatLng(" + geo.latitude + ", " + geo.longitude + "), new google.maps.LatLng(" + element.latitude + ", " + element.longitude + "),");
			}
			
			pwOut.println("];");
			pwOut.println("var userCoordinate = new google.maps.Polyline({		path: userCoorPath,		strokeColor: \"#FF0000\",		strokeOpacity: 1,		strokeWeight: 2		});");
			pwOut.println("userCoordinate.setMap(map);");
			pwOut.println("var infowindow = new google.maps.InfoWindow();");
			pwOut.println("var marker, i;");
			pwOut.println("for (i = 0; i < userCoor.length; i++) 		{  ");
			pwOut.println("marker = new google.maps.Marker			({				position: new google.maps.LatLng(userCoor[i][1], userCoor[i][2]),				map: map			});");
			pwOut.println("google.maps.event.addListener(marker, 'click', (function(marker, i) 		  {			return function() 			{			  infowindow.setContent(userCoor[i][0]);			  infowindow.open(map, marker);			}		  })(marker, i));");
			pwOut.println("	}");
			pwOut.println("}");
			pwOut.println("</script>    <script async defer");
			//pwOut.println("src=\"https://maps.googleapis.com/maps/api/js?key=AIzaSyAoqvNtUZsWrBunDLlVp_KxRzqK3Lsx8l0&callback=initMap\">");
			pwOut.println("src=\"https://maps.googleapis.com/maps/api/js?key=AIzaSyBpjKTI6j_EZRjVUiFFBbBsfZjzEI6WchA&signed_in=true&callback=initMap\">");
			pwOut.println("</script>  </body>" + driver.FULL_NAME + " BETA by Solomon Sonya and Suhail Mushtaq</html>");
			
			
			
			
			
			//terminate
			
			
			pwOut.flush();
			pwOut.close();
			
			if(verbose)
				driver.directive("Process COMPLETE!  Barring errors, file written to: " + fleMap.getCanonicalPath());
			
			if(open_upon_completion)
			{
				driver.directive(map_name_with_extension + " has been exported to " + fleMap.getCanonicalPath());
				
				if(Driver.isWindows)
					try	{	Process p = Runtime.getRuntime().exec("explorer.exe " + fleMap.getCanonicalPath());	}	catch(Exception e){}
			}
			
			return true;
		}
		catch(FileNotFoundException fnfe)
		{
			driver.directive("* * Hmm... I'm working on drawing map at location : " + fleMap);
		}
		
		catch(Exception e)
		{
			driver.eop(myClassName, "draw_map_connected_lines", e);
		}
		
		return false;
	}
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	

}

