/**
 * @author Solomon Sonya
 */

package Typed_URL;

import Driver.*;

import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.*;

public class Node_URL 
{
	public static volatile Driver driver = new Driver();
	public static final String myClassName = "Node_URL";
	
	/**e.g. Chrome or IE*/
	public String type = "";
	
	/**e.g. URL1, URL2, History*/
	public String key = "";
	
	/**e.g. www.google.com*/
	public String url = "";
	
	/**e.g. hkcu\software\microsoft\internet explorer\typedURLs*/
	public String location = "";
	
	
	public volatile String id = "";
	public volatile  String title = "";
	public volatile  String visit_count = "";
	public volatile  String typed_count = "";
	public volatile  String last_visit_time_webkit = "";
	public volatile  String last_visit_time_epoch = "";
	public volatile  String last_visit_time = "";
	public volatile  String hidden = "";
	
	public volatile boolean is_chrome_history_file = false;
	public volatile boolean is_IE_typed_URL = false;
	
	public static volatile boolean update_required = false;
	
	public volatile static TreeMap<String, Node_URL> tree_typed_url = new TreeMap<String, Node_URL>();
	
	public volatile String [] array = new String[8];
	
	public Node_URL(String TYPE, String KEY, String URL, String LOCATION)
	{
		try
		{						
			if(!tree_typed_url.containsKey(TYPE + "_" + KEY))
			{
				type = TYPE;//E.G. IE
				key = KEY;//URL1, URL2
				url = URL;//WWW.YOUTUBE.COM
				location = LOCATION;//HKCU\Software\Microsoft\Internet Explorer\TypedURLs
				
				tree_typed_url.put(TYPE + "_" + KEY,  this);
				update_required = true;
				
				//notify
				driver.sop("New typed URL history value --> " + this.toString(true, "\t"));
			}
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "Constructor - 1", e);
		}
	}
	
	
	
	
	
	
	public String toString(boolean print_table_header, String delimiter)
	{
		try
		{
			delimiter = delimiter + " ";
			
			if(print_table_header)
			{
				if(is_IE_typed_URL)
				{
					return  "url_type: " + type + delimiter + 
							"url_key: " + key + delimiter + 
							"url_value: " + url + delimiter + 
							"url_location: " + location + delimiter;
				}
				
				else if(is_chrome_history_file)
				{
					return  "url_type: " + type + delimiter + 
							"url_key: " + key + delimiter + 
							"url_value: " + url + delimiter + 
							"url_location: " + location + delimiter + 
							"url_title: " + title + delimiter + 
							"url_visit_count: " + visit_count + delimiter + 
							"url_last_visit_time: " + last_visit_time + delimiter + 
							"url_hidden: " + hidden + delimiter;																												
				}
				
			}
			
			//
			//OTW
			//
			
			if(is_IE_typed_URL)
			{
				return  type + delimiter + 
						key + delimiter + 
						url + delimiter + 
						location + delimiter;
			}
			
			else if(is_chrome_history_file)
			{
				return  type + delimiter + 
						key + delimiter + 
						url + delimiter + 
						location + delimiter + 
						title + delimiter + 
						visit_count + delimiter + 
						last_visit_time + delimiter + 
						hidden + delimiter;
			}
			
			
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "toString", e);
		}
		
		return this.url;
	}
	
	
	
	
	public static File export_typed_url(String delimiter, boolean open_file_upon_completion)
	{
		try
		{
			//enumerate
			Typed_URL_Extractor.enumerate_typed_urls(open_file_upon_completion);
			
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
			File fle = new File(path + "typed_url_history.txt");
			PrintWriter pwOut = new PrintWriter(new FileWriter(fle), true);
			
			File fle_table = new File(path + "typed_url_history_table.txt");
			PrintWriter pwOut_table = new PrintWriter(new FileWriter(fle_table), true);
			
			//write header
			pwOut_table.println("url_type" + delimiter + "url_key" + delimiter + "url_value" + delimiter + "url_location" + delimiter + "url_title" + delimiter + "url_visit_count" + delimiter + "url_last_time_visit" + delimiter + "url_hidden");
			
			//write data
			for(Node_URL url : tree_typed_url.values())
			{
				pwOut.println(url.toString(true, delimiter));												
				pwOut_table.println(url.toString(false, delimiter));
			}							
			
			
			pwOut.flush();
			pwOut.close();
			
			pwOut_table.flush();
			pwOut_table.close();
			
			driver.directive("Complete, if successful, URL history file has been written to " + fle.getCanonicalPath());			
			
			if(open_file_upon_completion && fle != null && fle.exists())
			{
				driver.open_file(fle);
			}
			
			if(open_file_upon_completion && fle_table != null && fle_table.exists())
			{
				driver.open_file(fle_table);
			}
			
			
			
			return fle;	
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "export_netstat_tree", e);
		}
		
		return null;
	}
	
	public String [] get_jtable_row()
	{
		try
		{
			array[0] = this.type;
			array[1] = this.key;
			array[2] = this.url;
			array[3] = this.location;
			array[4] = this.title;
			array[5] = this.visit_count;
			array[6] = this.last_visit_time;
			array[7] = this.hidden;
			
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "get_jtable_row", e);
		}
		
		return array;
	}
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	

}
