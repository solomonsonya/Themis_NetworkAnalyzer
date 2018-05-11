/**
 * The purpose of this class is to read the oui.txt file provided from http://standards-oui.ieee.org/oui.txt
 * 
 * I am adapting this class from the one I created in the Theia Project
 * 
 * @author Solomon Sonya
 */

package OUI_Parser;

import java.io.*;
import Driver.*;


import java.util.*;

import javax.swing.JFileChooser;


public class OUI_Parser extends Thread implements Runnable
{
	public static final String myClassName = "OUI_Parser";
	public static Driver driver = new Driver();
	public volatile File fleOUI = null;
	
	public volatile static String [] array = null;
	
	public static final String delimiter_get_mac = "#####";
	/**solo, do not change the text here unless you wish to change it in drivers of the sensor suite class!*/
	public static final String NOT_FOUND = "no results returned from selected query";
	//public static final String OUI_PATH = "/Resources/OUI/2016-02-08/oui.txt";
	public static final String OUI_PATH = "/Resources/OUI/2017-02-20/oui.txt";
	public static final int MAX_MAC_SEARCH_LENGTH = 30;
	public static final int ONLY_OUI_MAC_SIZE_STRIPPED = 6;
	public static final String DEFAULT_MAC_TOKEN = ":";
	
	public volatile String file_path = null;
	
	
	
	public volatile LinkedList<String> list_MAC = new LinkedList<String>();
	public volatile LinkedList<Node_OUI> list_MAC_Nodes = new LinkedList<Node_OUI>();
	
	private volatile Enumeration<String> enum_keys = null;
	private volatile ArrayList<String> array_list = null;
	private volatile LinkedList<String> linked_list = new LinkedList<String>();
	
	public volatile boolean import_file_from_jar_archive = false;
	

	public OUI_Parser(String filePath, boolean load_file_from_jar_archive)
	{
		try
		{
			file_path = filePath;
			import_file_from_jar_archive = load_file_from_jar_archive;
			
			driver.directive("Importing OUI (organizationally unique identifier) tuples...");
			this.start();							
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "Constructor - 1", e, false);
		}
	}	
	
	
	public void run()
	{
		try
		{
			//
			//attempt to open the file from within the jar
			//			
			parseFile(file_path, import_file_from_jar_archive);
						
		
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "run", e, false);
		}
	}
	
	/**
	 * ok to be null
	 * @param is
	 * @param path
	 * @param fle
	 * @return
	 */
	public boolean parseFile(String filePath_or_resource_within_jar_path, boolean use_file_included_within_jar_package)
	{
		try
		{
			BufferedReader brIn = null;
			String file_path = filePath_or_resource_within_jar_path;
			File fle = null;
			
			//
			//read file within JAR archive
			//
			if(use_file_included_within_jar_package)
			{
				try
				{
				
					InputStream is = driver.getFile_within_JAR(OUI_PATH);
					
					brIn = new BufferedReader(new InputStreamReader(is, "UTF-8"));
					
					//try and set the file
					try
					{
						fle = new File(getClass().getClassLoader().getResource(filePath_or_resource_within_jar_path).getFile());					
					}
					catch(Exception e)
					{
						fle = null;
					}
					
					driver.sop("OUI resource was successfully located within archive at " + filePath_or_resource_within_jar_path);
					
					file_path = filePath_or_resource_within_jar_path;
				}
				catch(Exception e)
				{
					driver.sop("\n\nINTERNAL ERROR! Resource OUI.txt file not found within archive. ATTEMPTING TO QUERY USER FOR LOCATION NOW...");
					return parseFile(null, false);
				}
			}
			
			//
			//File from direct path provided from command line
			//
			else if(filePath_or_resource_within_jar_path != null && !filePath_or_resource_within_jar_path.trim().equals(""))
			{
				fle = new File(filePath_or_resource_within_jar_path);
				
				file_path = fle.getCanonicalPath();
				
				//
				//commence
				//			
				brIn = new BufferedReader(new FileReader(fle));
			}
			
			//
			//query user via file dialog
			//
			else
			{								
				//get OUI File
				fle = driver.querySelectFile(true, "Please select OUI (Organizationally Unique Identifier) Input File", JFileChooser.FILES_ONLY, false, false);
				
				if(fle == null || !fle.isFile() || !fle.exists())
				{
					driver.sop("\n\n> > > ERROR! INVALID FILE SPECIFIED IN " + myClassName + ". Unable to begin parser...");
					return false;
				}
				
				file_path = fle.getCanonicalPath();
				
				//
				//commence
				//			
				brIn = new BufferedReader(new FileReader(fle));
			}
			
			
			
						
			//good file selected, store
			fleOUI = fle;			
			
			System.out.println("Commensing " + myClassName + " functions on file: " + file_path);
			
			int linesRead = 0;									
			String line = "";
			Node_OUI node = null;			
			
			while((line = brIn.readLine())!=null)
			{
				try
				{
					++linesRead;
					
					if(linesRead % 1000 == 0)
						driver.sp(".");
					
					line = line.trim();
					
					/*currently, the version of file looks similar to the following:
					00-22-83   (hex)		Juniper Networks
					002283     (base 16)		Juniper Networks
								1133 Innovation Way
								Sunnyvale  CA  94089
								US*/
					
					//the first line, will be a throw-away (i'd have to strip out the "-"
					//the next line, if it contains"base 16" will be what we care about to signify a new node
					
					//
					//GET OUI MAC AND COMPANY
					//
					if(line.contains("(base 16)"))
					{
						//found new OUI MAC
						array = line.split("\\(base 16\\)");
						
						if(array == null || array.length < 2)
						{
							driver.sop("invalid line specification at index: "  + linesRead + " actual line-->" + line);
							continue;
						}
						
						//
						//Store MAC and VENDOR Company Name
						//
						node = new Node_OUI();
						node.MAC_STRIPPED = array[0].toLowerCase().trim();
						
						//strip just in case
						node.MAC_STRIPPED = driver.strip_MAC(node.MAC_STRIPPED);
						
						node.COMPANY = array[1].trim();		
						
						if(node.MAC_STRIPPED == null || node.MAC_STRIPPED.trim().equals(""))
						{
							driver.sop("unknown address entered at line: " + linesRead + " line-->" + line + "<-- SKIPPING!!!");
							continue;
						}
						
						//
						//Store Address
						//
						node.ADDRESS = brIn.readLine().trim();
						linesRead++;
						
						//
						//Store City and ZIP
						//
						node.CITY_ZIP = brIn.readLine().trim();
						linesRead++;
						
						try
						{
							array = node.CITY_ZIP.trim().split(" ");
							
							node.ZIP = array[array.length-1];
							
							try 
							{ 								
								node.zip = Integer.parseInt(node.ZIP.trim());	
								
								//good zip, so take the city now as well
								node.CITY = array[0];
								for(int i = 1; i < array.length-1; i++)
									node.CITY = node.CITY + " " + array[i];
							}
							catch(Exception e)
							{
								//set city to city zip
								node.CITY = node.CITY_ZIP;
								node.zip = -1;
								node.ZIP = "-1";
							}
							
						}
						catch(Exception e)
						{
							driver.sop("NOTE: unable to separate city and zip in line: " + linesRead + " line-->" + line);
							node.CITY = node.CITY_ZIP;
							node.ZIP = node.CITY_ZIP;
						}
						
						//
						//Store Country Code
						//
						node.COUNTRY_CODE = brIn.readLine().trim();
						linesRead++;
						
						//
						//populate!
						//
						Node_OUI.tree_OUI_MAC.put(node.MAC_STRIPPED, node);
					}
					
				}
				catch(Exception e)
				{
					driver.sop(myClassName + " class: check index: " + linesRead);
					continue;
				}
			}
			
			driver.sop("\n\n" + myClassName + " complete on file: " + file_path + ".  Num lines read: " + linesRead + ".  Unique OUI MAC addresses: " + Node_OUI.tree_OUI_MAC.size());
			
			
			//launch default if we're loading from the internal JAR
			if(import_file_from_jar_archive)
			{
				//driver.sop("\nI will attempt to establish server socket for you. Remember to use the help if you need to configure the server socket differently. Standby...\n\n");
						
			}
			
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "parseFile", e, true);
		}
		
		return false;
	}
	
	public LinkedList<String> get_keys(Hashtable hashtbl, boolean sort_entries)
	{
		try
		{
			//retrieve enumeration set
			this.enum_keys = hashtbl.keys();
			
			try		{		array_list.clear();			} catch(Exception e){}
			
			array_list = null;
			
			//convert enumeration set to arraylist
			array_list = Collections.list(enum_keys);
			
			if(array_list == null || array_list.size() < 1)
				return null;
			
			//clear prev entries
			try	{	linked_list.clear();	}	catch(Exception e){linked_list = null; linked_list = new LinkedList<String>();}
			
			//convert arraylist to linkedlist
			for(int i = 0; array_list != null && i < array_list.size(); i++)
			{
				try
				{
					this.linked_list.add(array_list.get(i));
				}
				catch(Exception e)
				{
					driver.sop("check get_keys in " + myClassName + " index: " + i);
				}
			}
			
			array_list.clear();
			array_list = null;
			
			//sort
			if(sort_entries)
			{
				try	{ Collections.sort(linked_list);	}	catch(Exception ee){driver.sop("\ncheck get_keys sorting in " + myClassName);}
			}
			
			return linked_list;
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "get_keys", e, false);
		}
		
		return null;
	}
	
	
	
	
	public int count_MACs(Hashtable hashtbl)
	{
		try
		{
			if(hashtbl == null)
			{
				driver.sop("\nNOTE: OUI import list is empty!!!");
				return 0;
			}
			
			return hashtbl.size();
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "print_MACs", e, false);
		}
		
		return -1;
	}
	
	public LinkedList<Node_OUI> get_MAC_Nodes(Hashtable hashtbl)
	{
		try
		{
			if(hashtbl == null)
			{				
				return null;
			}
			
			//otherwise, print received data to terminal
			this.list_MAC_Nodes = new LinkedList<Node_OUI>(hashtbl.values());
			
			return list_MAC_Nodes;						
			
		}
		catch(Exception e)
		{
			driver.sop("Exception caught in  get_MAC_Nodes  in class: " + myClassName + " message: " + e.getLocalizedMessage());			
		}
		
		return null;
	}
				
	public String get_MAC_Data_Single_MAC(Hashtable hashtbl, String mac, String mac_token, String delimiter)
	{
		try
		{						
			if(mac == null || mac.trim().equals(""))
				return NOT_FOUND + " * *";
			
			/*if(mac.trim().length() > MAX_MAC_SEARCH_LENGTH)
				mac = mac.substring(0,MAX_MAC_SEARCH_LENGTH-1);
			
			mac = mac.toUpperCase().trim();
			
			//strip
			mac = driver.strip_MAC(mac);
							
			Node_OUI node = (Node_OUI)hashtbl.get(mac);*/
			
			Node_OUI node = this.DEPRECATED_get_MAC(mac);
			
			if(node == null)
			{
				return NOT_FOUND + " * * * ";
			}
			
			return node.getData(delimiter, mac_token, true);		
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "print_MACs", e, false);
		}
		
		return NOT_FOUND + " * * * *";
	}
	
	
	public static Node_OUI DEPRECATED_get_MAC(String mac)
	{
		try
		{						
			if(mac == null || mac.trim().equals(""))
				return null;
			
			//strip
			mac = driver.strip_MAC(mac);
			
			//shorten
			if(mac.trim().length() > MAX_MAC_SEARCH_LENGTH)
				mac = mac.substring(0,MAX_MAC_SEARCH_LENGTH-1);
			
			//trim
			mac = mac.toLowerCase().trim();											
				
			Node_OUI node = Node_OUI.tree_OUI_MAC.get(mac);		
			
			//what if receive: a4:77:33:3b:e3:be
			if(node == null && mac.length() >= ONLY_OUI_MAC_SIZE_STRIPPED)
			{
				//try one more time on even more reduced set to look only at the first 6 bytes
				mac = mac.substring(0,ONLY_OUI_MAC_SIZE_STRIPPED);
				
				//driver.sop("searching: " + mac);
				node = Node_OUI.tree_OUI_MAC.get(mac);	
			}
			
			return node;
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "get_MAC", e, false);
		}
		
		return null;
	}
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
}
