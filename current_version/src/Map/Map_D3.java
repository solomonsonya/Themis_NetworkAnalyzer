package Map;

import Driver.*;
import Profile.*;
import GEO_Location.*;
import javax.swing.*;

import java.awt.BorderLayout;
import java.awt.event.*;
import java.io.*;
import java.io.PrintWriter;
import java.util.ConcurrentModificationException;
import java.util.Set;

public class Map_D3 extends JPanel implements ActionListener
{
	public static final String myClassName = "Map_D3";
	public static volatile Driver driver = new Driver();

	Timer tmr = null;
	public volatile boolean handle_interrupt = true;
	
	public static final String top_folder = "." + File.separator + Driver.NAME + File.separator + "map" + File.separator; 
	
	File fleDependency1 = new File(top_folder + "d3.v3.min.js");
	File fleDependency2 = new File(top_folder + "datamaps.world.min.js");
	File fleDependency3 = new File(top_folder + "topojson.v1.min.js");
	
	public static final String path_dependency1_in_jar = "/Map/d3.v3.min.js";
	public static final String path_dependency2_in_jar = "/Map/datamaps.world.min.js";
	public static final String path_dependency3_in_jar = "/Map/topojson.v1.min.js";
	
	public volatile String map_name = "connections_map.html";
	//public volatile WEB_COMPONENT component = null;
	
	public static volatile Set<String> key_set_geo_location = null; 
	public static volatile GEO_Location geo_update = null;
	
	public Map_D3()
	{
		try
		{
			tmr = new Timer(120000, this);
			tmr.start();
			
			
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
			if(ae.getSource() == this.tmr)
			{
				process_interrupt();
			}
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "ae", e);
		}
		
	}
	
	public boolean process_interrupt()
	{
		try
		{
			if(Driver.GEO_LOCATION_ME == null)
				Driver.GEO_LOCATION_ME = new GEO_Location();
			
			if(!handle_interrupt)
				return false;
			
			if(GEO_Location.TREE_GEO_LOCATION == null || GEO_Location.TREE_GEO_LOCATION.isEmpty())
				return false;
			
			handle_interrupt = false;						
			
			ensure_dependencies();
			
			//overwrite the file
			PrintWriter pwOut = new PrintWriter(new FileWriter(top_folder + map_name));
			
			pwOut.println("<!DOCTYPE html>");
			pwOut.println("<meta charset=\"utf-8\">");
			pwOut.println("<meta http-equiv=\"refresh\" content=\"60\">");
			pwOut.println("<body>");
			pwOut.println("  <script src=\"d3.v3.min.js\"></script>");
			pwOut.println("  <script src=\"topojson.v1.min.js\"></script> "); 
			pwOut.println("  <script src=\"datamaps.world.min.js?v=1\"></script>  ");
			pwOut.println("  <div id=\"container1\" style=\"position: relative; width: 2200px;height: 950px;\"></div>\");");
			 
			     
			pwOut.println("     <script>");
			       //basic map config with custom fills, mercator projection
			pwOut.println("      var map = new Datamap({");
			pwOut.println("       scope: 'world',");
			pwOut.println("        element: document.getElementById('container1'),");
			pwOut.println("        projection: 'mercator',");
			        
			pwOut.println("        fills: {");
			pwOut.println("          defaultFill: '#bab4b4',");
			pwOut.println("          clr1: 'rgba(33,150,144,0.9)',");
			pwOut.println("          danger: 'red',");
			pwOut.println("		  visited: 'yellow'");
			pwOut.println("        },");
					
					
			        
			pwOut.println("       data: {");
			pwOut.println("          USA: {fillKey: 'visited' },");
			pwOut.println("          RUS: {fillKey: 'danger' },");
			pwOut.println("          CAN: {fillKey: 'clr1' },");
			pwOut.println("          BRA: {fillKey: 'danger' },");
			pwOut.println("          ARG: {fillKey: 'danger'},");
			pwOut.println("         COL: {fillKey: 'danger' },");
			pwOut.println("         AUS: {fillKey: 'danger' },");
			pwOut.println("         ZAF: {fillKey: 'danger' },");
			pwOut.println("          MAD: {fillKey: 'danger' },");
			pwOut.println("		  HUN: {fillKey: 'danger' },");
			pwOut.println("		  NOR: {fillKey: 'visited' },");
			pwOut.println("        }, ");
			pwOut.println("        done: function(datamap) {");
			pwOut.println("           datamap.svg.call(d3.behavior.zoom().on(\"zoom\", redraw));");

			pwOut.println("          function redraw() {");
			pwOut.println("                datamap.svg.selectAll(\"g\").attr(\"transform\", \"translate(\" + d3.event.translate + \")scale(\" + d3.event.scale + \")\");");
			pwOut.println("           }");
			pwOut.println("        }");
			pwOut.println("      })");
			      
			 pwOut.println("map.arc([");
			 
			 
			 key_set_geo_location = GEO_Location.TREE_GEO_LOCATION.keySet();
				
			if(key_set_geo_location == null || key_set_geo_location.isEmpty())
				return false;
				
				
			for(String key : key_set_geo_location)
			{
				if(key == null || key.equals(""))
					continue;

				geo_update = GEO_Location.TREE_GEO_LOCATION.get(key);

				if(geo_update == null)
					continue;
				 				 
				 pwOut.println("{");
				 pwOut.println("       origin: {");
				 pwOut.println("latitude: " + GEO_Location.origin_latitude + ",");
				 pwOut.println("           longitude: " + GEO_Location.origin_longitude + "");
				 pwOut.println("        },");
				 pwOut.println("       destination: {");
				 pwOut.println("          latitude: " + geo_update.latitude + ", ");
				 pwOut.println("          longitude: " + geo_update.longitude + "");
				 pwOut.println("          }");
				 pwOut.println("          },");
					 
			}
			 
			 
//			 for(GEO_Location geo : GEO_Location.TREE_GEO_LOCATION.values())
//			 {
//				 if(geo == null)
//					 continue;
//				 
//				 pwOut.println("{");
//				 pwOut.println("       origin: {");
//				 pwOut.println("latitude: " + GEO_Location.origin_latitude + ",");
//				 pwOut.println("           longitude: " + GEO_Location.origin_longitude + "");
//				 pwOut.println("        },");
//				 pwOut.println("       destination: {");
//				 pwOut.println("          latitude: " + geo.latitude + ", ");
//				 pwOut.println("          longitude: " + geo.longitude + "");
//				 pwOut.println("          }");
//				 pwOut.println("          },");
//				 
//			 }
			 
			 pwOut.println("  ], ");
			  
			 pwOut.println("   { ");
			 pwOut.println(" 		strokeWidth: 2, ");
			 pwOut.println(" 		arcSharpness: 1, ");
			 pwOut.println(" 		animationSpeed: 600, ");
			 pwOut.println(" 		strokeColor: 'blue', ");	
				
			 pwOut.println("  } ");
			  
			  
			  
			 pwOut.println("   ); ");
			 
			 
		       
		      
		       //bubbles, custom popup on hover template
//		     map.bubbles([
//		       {name: 'Hot', latitude: 21.32, longitude: 5.32, radius: 10, fillKey: 'gt50'},
//		       {name: 'Chilly', latitude: -25.32, longitude: 120.32, radius: 18, fillKey: 'lt50'},
//		       {name: 'Hot again', latitude: 21.32, longitude: -84.32, radius: 8, fillKey: 'gt50'},
//
//		     ], {
//			 pwOut.println("    popupTemplate: function(geo, data) { ");
//			 pwOut.println("      return \"<div class='hoverinfo'>It is \" + data.name + \"</div>\"; ");
//			 pwOut.println("     } ");
//			 pwOut.println("   }); ");
			 pwOut.println("  </script> ");
			 pwOut.println("  </body> ");
			      
			
			pwOut.flush();
			try	{	pwOut.close();} catch(Exception e){}
			handle_interrupt = true;
			return true;
		}
		catch(ConcurrentModificationException cme)
		{
			driver.directive("Holdfast, I am currently modifying the list entries in maps.");
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "process_interrupt", e);
		}
		
		handle_interrupt = true;
		
		return false;
	}
	
	
	public boolean ensure_dependencies()
	{
		try
		{
			if(fleDependency1 == null || !fleDependency1.isFile() || !fleDependency1.exists())
			{
				driver.write_dependency_file(fleDependency1, this.path_dependency1_in_jar);
			}
			
			if(fleDependency2 == null || !fleDependency2.isFile() || !fleDependency2.exists())
			{
				driver.write_dependency_file(fleDependency2, path_dependency2_in_jar);
			}
			
			if(fleDependency3 == null || !fleDependency3.isFile() || !fleDependency3.exists())
			{
				driver.write_dependency_file(fleDependency3, path_dependency3_in_jar);
			}
			
			/*if(component == null)
			{
				component = new WEB_COMPONENT(map_name);
				this.add(BorderLayout.CENTER, component);
			}*/
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "ensure_dependencies", e);
		}
		
		return false;
	}
	
	
	
	
	
}
