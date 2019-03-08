/**
 * @author Solomon Sonya
 */

package Process;

import Driver.*;
import GEO_Location.GEO_Location;
import Map.Node_Map_Details;
import Profile.Resolution;

import java.io.*;
import java.util.*;
import java.awt.event.*;

public class Node_Process extends Thread implements Runnable, ActionListener 
{
	public static volatile Driver driver = new Driver();
	public static final String myClassName = "Node_Process";
	
	public static Process_Solomon process_wmic_tasklist = new Process_Solomon(Process_Solomon.execution_action_WMIC_PROCESS);
	
	public static volatile LinkedList<Node_Process> printed_nodes = new LinkedList<Node_Process>();
	
	public static volatile LinkedList<Node_Map_Details> list_map_details = new LinkedList<Node_Map_Details>();
	
	/**
	 * every process stays here
	 */
	public static volatile TreeMap<String, Node_Process> tree_process = new TreeMap<String, Node_Process>();
	
	/**
	 * processes identified to be a parent of another are added here
	 */
	public static volatile TreeMap<String, Node_Process> tree_parent_process = new TreeMap<String, Node_Process>();
	
	public static volatile LinkedList<String> list_PID_TO_IGNORE = new LinkedList<String>();
	public static volatile LinkedList<String> list_PROCESS_NAMES_TO_IGNORE = new LinkedList<String>();
	
	public volatile Node_Process parent_process = null;
	
	public volatile LinkedList<Node_Process> list_offspring_process = null;
	
	public volatile long first_detection_time = System.currentTimeMillis();
	public volatile long last_detection_time = System.currentTimeMillis();
	
	public volatile String last_detection_time_text = driver.getTime_Specified_Hyphenated_with_seconds();
	public volatile String first_detection_time_text = driver.getTime_Specified_Hyphenated_with_seconds();
	
	public volatile static long current_time = 0;
	
	/**Keeps list of netstat objects linked to this process*/
	public volatile LinkedList<Node_Netstat> list_netstat = null;
	
	public volatile String value = "";
	public volatile String netstat_value = "";
	
	public volatile String array[] = new String[54];
	
	//tasklist
	public volatile String 	process_name = "",
			PID = "",
			session_name = "",
			session_number = "",
			mem_usage = "",
			status = "",
			user_name = "",
			cpu_time = "",
			window_title = "";
	
	public volatile String parent_PID = "";
	public volatile String 	parent_process_name = "";
	//wmic process
	//Node,Caption,CommandLine,CreationClassName,CreationDate,CSCreationClassName,CSName,Description,ExecutablePath,ExecutionState,Handle,HandleCount,InstallDate,KernelModeTime,MaximumWorkingSetSize,MinimumWorkingSetSize,Name,OSCreationClassName,OSName,OtherOperationCount,OtherTransferCount,PageFaults,PageFileUsage,ParentProcessId,PeakPageFileUsage,PeakVirtualSize,PeakWorkingSetSize,Priority,PrivatePageCount,ProcessId,QuotaNonPagedPoolUsage,QuotaPagedPoolUsage,QuotaPeakNonPagedPoolUsage,QuotaPeakPagedPoolUsage,ReadOperationCount,ReadTransferCount,SessionId,Status,TerminationDate,ThreadCount,UserModeTime,VirtualSize,WindowsVersion,WorkingSetSize,WriteOperationCount,WriteTransferCount
	String Node = ""; 
	String Caption = ""; 
	String CommandLine = ""; 
	String CreationClassName = ""; 
	String CreationDate = ""; 
	String CSCreationClassName = ""; 
	String CSName = ""; 
	String Description = ""; 
	String ExecutablePath = ""; 
	String ExecutionState = ""; 
	String Handle = ""; 
	String HandleCount = ""; 
	String InstallDate = ""; 
	String KernelModeTime = ""; 
	String MaximumWorkingSetSize = ""; 
	String MinimumWorkingSetSize = ""; 
	String Name = ""; 
	String OSCreationClassName = ""; 
	String OSName = ""; 
	String OtherOperationCount = ""; 
	String OtherTransferCount = ""; 
	String PageFaults = ""; 
	String PageFileUsage = ""; 
	String ParentProcessId = ""; 
	String PeakPageFileUsage = ""; 
	String PeakVirtualSize = ""; 
	String PeakWorkingSetSize = ""; 
	String Priority = ""; 
	String PrivatePageCount = ""; 
	String ProcessId = ""; 
	String QuotaNonPagedPoolUsage = ""; 
	String QuotaPagedPoolUsage = ""; 
	String QuotaPeakNonPagedPoolUsage = ""; 
	String QuotaPeakPagedPoolUsage = ""; 
	String ReadOperationCount = ""; 
	String ReadTransferCount = ""; 
	String SessionId = ""; 
	String Status = ""; 
	String TerminationDate = ""; 
	String ThreadCount = ""; 
	String UserModeTime = ""; 
	String VirtualSize = ""; 
	String WindowsVersion = ""; 
	String WorkingSetSize = ""; 
	String WriteOperationCount = ""; 
	String WriteTransferCount = "";
	
	public volatile String running_state = "RUNNING";
	
	public static volatile boolean PROCESS_ORBITER_ENABLED = false;
	private volatile boolean process_interrupt = true;
	public volatile javax.swing.Timer tmr_interrupt = null;
	public volatile int interrupt_millis = 4000;
	
	public volatile String str = "";
	
	public static volatile boolean update_required = false;
	
	public Node_Process(int interrpt_millis)
	{
		try
		{	
			interrupt_millis = interrpt_millis;			
			this.start();
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "Constructor - interrupt_millis", e);
		}
	}
	
	public Node_Process(String pid, String PROCESS_NAME)
	{
		try
		{
			PID = pid;
			
			//
			//ignore adding processes found on the list
			//
			if(Node_Process.list_PROCESS_NAMES_TO_IGNORE.contains(PROCESS_NAME.toLowerCase()))
			{
				//do nothing
			}
			
			//link			
			else
			{
				//otw, process name was not found on the ignore list, add to the list!
				if(!tree_process.containsKey(PID))
				{
					tree_process.put(PID,  this);	
					
					update_required = true;
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
			tmr_interrupt = new javax.swing.Timer(interrupt_millis, this);
			tmr_interrupt.start(); 
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
			if(ae.getSource() == tmr_interrupt && this.PROCESS_ORBITER_ENABLED)
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
			if(!this.process_interrupt)
				return false;
			
			process_interrupt = false;
			
			if(driver.isWindows)			
				process_wmic_tasklist.exec("wmic process get /format:csv");
			
			process_interrupt = true;
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "process_interrupt", e);
		}
		
		process_interrupt = true;
		return false;
	}
	
	public boolean set_parent_process()
	{
		try
		{
			//determine if this is an ignore word...
			if(this.list_PROCESS_NAMES_TO_IGNORE.contains(this.process_name.toLowerCase()))
				return false;
			
			if(this.list_PID_TO_IGNORE.contains(this.PID) || this.list_PID_TO_IGNORE.contains(this.ParentProcessId))
				return false;
			
			//don't continue if we have already set the parent process
			if(this.parent_process != null)
				return true;
			
			//procure the parent if we have it yet...
			if(this.tree_process.containsKey(this.ParentProcessId))
			{
				this.parent_process = this.tree_process.get(ParentProcessId);
				
				if(parent_process == null)
					return false;
				
				this.parent_process_name = parent_process.process_name;
				
				driver.sop("PID [" + this.PID + "] - " + this.process_name + " linked to --> [" + ParentProcessId + "] - " + parent_process_name);
				
				//ensure the node is not on the ignore list
				if(this.list_PROCESS_NAMES_TO_IGNORE.contains(parent_process.process_name.toLowerCase()))
					return false;
				
				if(this.list_PID_TO_IGNORE.contains(parent_process.PID) || this.list_PID_TO_IGNORE.contains(parent_process.ParentProcessId))
					return false;
				
				//we have a good parent here, ensure we are on the parent's list of processes
				if(parent_process.list_offspring_process == null)
				{
					parent_process.list_offspring_process = new LinkedList<Node_Process>();
					parent_process.list_offspring_process.add(this);
				}
				else if(!parent_process.list_offspring_process.contains(this))
				{
					parent_process.list_offspring_process.add(this);
				}				
				
				//
				//store the parent to the parent tree
				//
				
				//we have a good parent, add to the list of parent processes!
				if(!this.tree_parent_process.containsKey(parent_process.PID))
				{
					this.tree_parent_process.put(parent_process.PID, parent_process);	
					
					update_required = true;
				}
				
			}
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "set_parent_process", e);
		}
		
		return false;
		
	}
	
	public static boolean print_super_parents(LinkedList<Node_Process> list_parent, PrintWriter pwOut)
	{
		try
		{
			if(list_parent == null || list_parent.isEmpty())
				return false;
			
			//
			//print the parent, followed by all offspring
			//
			for(Node_Process parent : list_parent)
			{
				if(parent == null)
					continue;	
				
				
				//print all "super parents" first.  Super Parents are parent processes (that have offspring), but the parent, does not
				//have a parent.  For instance, right now, we could have chrome.exe that spawns separate chrome.exe daemons
				//printing as is, we'll get chrome.exe with it's subprocess chrome.exe daemons, but then, explorer.exe will print
				//with chrome.exe as a offspring, and then have the details printed twice
				//so to alleviate this hopefully, find and print all processes that do not have parents first.  This is my super parent
				//nomenclature, and track all nodes that have been printed, such that we don't have dupliates printed again
				
				//find the super parents if their parents have not been found, otherwise, skip to be printed by the other function
				if(parent.parent_process != null)
					continue;
						
				
				//skip if node has already been printed
				if(printed_nodes.contains(parent))
					continue;						
				
				//print node
				if(pwOut != null)
					pwOut.println(parent.toString("\t", true, true, "\n\t"));
				else							
					driver.directive(parent.toString("\t", true, true, "\n\t"));
				
				printed_nodes.add(parent);
				
				//print offspring
				if(parent.list_offspring_process == null || parent.list_offspring_process.isEmpty())
					continue;
				
				//sort the list of offspring
				try
				{
					Collections.sort(parent.list_offspring_process, new Comparator<Node_Process>()
					{
						public int compare(Node_Process t1, Node_Process t2)
						{
							return t1.process_name.compareToIgnoreCase(t2.process_name);
						}						
						
					});
				}catch(Exception ee){}
				
				for(Node_Process offspring : parent.list_offspring_process)
				{
					if(offspring == null)
						continue;
					
//					if(printed_nodes.contains(offspring))
//						continue;
					
					if(pwOut != null)
						pwOut.println("\t" + offspring.toString("\t", true, true, "\n\t\t"));
					else							
						driver.directive("\t" + offspring.toString("\t", true, true, "\n\t\t"));
					
					printed_nodes.add(offspring);
				}
				
			}
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "print_super_parents", e);
		}
		
		return false;
	}
	
	public static boolean update_node_parents()
	{
		try
		{
			if(Node_Process.tree_process == null || Node_Process.tree_process.isEmpty())
				return false;
			
			LinkedList<Node_Process> list = new LinkedList<Node_Process>(tree_process.values());
			
			for(Node_Process node : list)
				node.set_parent_process();
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "update_node_parents", e);
		}
		
		return false;
	}
	
	public static boolean print_process_tree(PrintWriter pwOut)
	{
		try
		{
			//
			//clear printed_nodes
			//
			try	{	printed_nodes.clear();	}	catch(Exception e)	{	printed_nodes = new LinkedList<Node_Process>();	}		
			
			//
			//update list to see if offspring process can now be linked back with it's parent
			//
			update_node_parents();
			
			//
			//update netstat entries with parents as well
			//
			Node_Netstat.update_netstat_parent();
			
			//
			//GET PARENT LIST
			//
			LinkedList<Node_Process> list_parent = new LinkedList<Node_Process>(Node_Process.tree_parent_process.values());
									
			//
			//sort based on name
			//
			try
			{
				Collections.sort(list_parent, new Comparator<Node_Process>()
				{
					public int compare(Node_Process t1, Node_Process t2)
					{
						return t1.process_name.compareToIgnoreCase(t2.process_name);
					}						
					
				});
			}
			catch(Exception e)
			{
				
			}
			
			//
			//print the parent, followed by all offspring
			//
			for(Node_Process parent : list_parent)
			{
				if(parent == null)
					continue;
				
				//print all "super parents" first.  Super Parents are parent processes (that have offspring), but the parent, does not
				//have a parent.  For instance, right now, we could have chrome.exe that spawns separate chrome.exe daemons
				//printing as is, we'll get chrome.exe with it's subprocess chrome.exe daemons, but then, explorer.exe will print
				//with chrome.exe as a offspring, and then have the details printed twice
				//so to alleviate this hopefully, find and print all processes that do not have parents first.  This is my super parent
				//nomenclature, and track all nodes that have been printed, such that we don't have dupliates printed again
				print_super_parents(list_parent, pwOut);
				
				//skip if node has already been printed
				if(printed_nodes.contains(parent))
					continue;						
				
				//print node
				if(pwOut != null)
					pwOut.println(parent.toString("\t", true, true, "\n\t"));
				else							
					driver.directive(parent.toString("\t", true, true, "\n\t"));
				
				printed_nodes.add(parent);
				
				//print offspring
				if(parent.list_offspring_process == null || parent.list_offspring_process.isEmpty())
					continue;
				
				//sort the list of offspring
				try
				{
					Collections.sort(parent.list_offspring_process, new Comparator<Node_Process>()
					{
						public int compare(Node_Process t1, Node_Process t2)
						{
							return t1.process_name.compareToIgnoreCase(t2.process_name);
						}						
						
					});
				}catch(Exception ee){}
				
				for(Node_Process offspring : parent.list_offspring_process)
				{
					if(offspring == null)
						continue;
					
//					if(printed_nodes.contains(offspring))
//						continue;
					
					if(pwOut != null)
						pwOut.println("\t" + offspring.toString("\t", true, true, "\n\t\t"));
					else							
						driver.directive("\t" + offspring.toString("\t", true, true, "\n\t\t"));
					
					printed_nodes.add(offspring);
				}
				
			}
			
			//
			//Print all orphaned processes
			//
			LinkedList<Node_Process> list_orphans = new LinkedList<Node_Process>(Node_Process.tree_process.values());
			
			//
			//sort based on name
			//
			try
			{
				Collections.sort(list_orphans, new Comparator<Node_Process>()
				{
					public int compare(Node_Process t1, Node_Process t2)
					{
						return t1.process_name.compareToIgnoreCase(t2.process_name);
					}						
					
				});
			}
			catch(Exception e)
			{
				
			}
			
			//
			//print orphans
			//
			for(Node_Process orphan : list_orphans)
			{
				if(orphan == null)
					continue;
				
				if(printed_nodes.contains(orphan))
					continue;
				
				//skip the orphan if it has a parent, bcs it was printed above
				if(orphan.parent_process != null && Node_Process.tree_parent_process.containsValue(orphan.parent_process))
					continue;
				
				if(pwOut != null)
					pwOut.println(orphan.toString("\t", true, true, "\n\t"));
				else							
					driver.directive(orphan.toString("\t", true, true, "\n\t"));
				
				printed_nodes.add(orphan);
			}
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "print_process_tree", e);
		}
		
		return false;
	}
	
	public static boolean print_process_dump(String delimiter, boolean include_header)
	{
		try
		{
			if(Node_Process.tree_process == null || Node_Process.tree_process.isEmpty())
			{
				driver.directive("Punt! No Process nodes entries collected yet!");
				return false;
			}
			
			//Get list of processes
			LinkedList<Node_Process> list = new LinkedList<Node_Process>(Node_Process.tree_process.values());
			
			if(list == null || list.isEmpty())
			{
				driver.directive("Punt!!! No Process nodes entries collected yet!");
				return false;
			}
			
			for(Node_Process node : list)
			{
				if(node == null)
					continue;
				
				driver.directive(node.toString(delimiter, include_header, true, "\n\t"));
			}
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "print_process_dump", e);
		}
		
		return false;
	}
	
	public String toString(String delimiter, boolean include_header, boolean include_netstat, String netstat_starting_location)
	{
		try
		{
			delimiter = delimiter + " ";
			
			if(include_header)
			{
				return 	"process_name: " + process_name + delimiter + 
						"PID: " + PID   + delimiter + 
						"parent_PID: " + ParentProcessId + delimiter +
						"parent_process_name: " + parent_process_name + delimiter +
						"ExecutablePath: " + ExecutablePath + delimiter +
						"CommandLine: " + CommandLine + delimiter +
						 
						
						/*"session_name: " + session_name + delimiter + 
						"session_number: " + session_number + delimiter + 
						"mem_usage: " + mem_usage + delimiter + 
						"status: " + status  + delimiter + 
						"user_name: " + user_name + delimiter + 
						"cpu_time: " + cpu_time + delimiter + 
						"window_title: " + window_title + delimiter + */
						
						"Running State: " + this.running_state + delimiter + 
						"First Detection Time: " + this.first_detection_time_text + delimiter +
						"First Detection Time_millis: " + this.first_detection_time + delimiter + 
						"Last Detection Time: " + this.last_detection_time_text + delimiter +
						"Last Detection Time_millis: " + this.last_detection_time + delimiter + 
						
						"Node: " + Node + delimiter + 
						"Caption: " + Caption + delimiter + 						 
						"CreationClassName: " + CreationClassName + delimiter + 
						"CreationDate: " + CreationDate + delimiter + 
						"CSCreationClassName: " + CSCreationClassName + delimiter + 
						"CSName: " + CSName + delimiter + 
						"Description: " + Description + delimiter + 
						
						"ExecutionState: " + ExecutionState + delimiter + 
						"Handle: " + Handle + delimiter + 
						"HandleCount: " + HandleCount + delimiter + 
						"InstallDate: " + InstallDate + delimiter + 
						"KernelModeTime: " + KernelModeTime + delimiter + 
						"MaximumWorkingSetSize: " + MaximumWorkingSetSize + delimiter + 
						"MinimumWorkingSetSize: " + MinimumWorkingSetSize + delimiter + 
						"Name: " + Name + delimiter + 
						"OSCreationClassName: " + OSCreationClassName + delimiter + 
						"OSName: " + OSName + delimiter + 
						"OtherOperationCount: " + OtherOperationCount + delimiter + 
						"OtherTransferCount: " + OtherTransferCount + delimiter + 
						"PageFaults: " + PageFaults + delimiter + 
						"PageFileUsage: " + PageFileUsage + delimiter + 						 
						"PeakPageFileUsage: " + PeakPageFileUsage + delimiter + 
						"PeakVirtualSize: " + PeakVirtualSize + delimiter + 
						"PeakWorkingSetSize: " + PeakWorkingSetSize + delimiter + 
						"Priority: " + Priority + delimiter + 
						"PrivatePageCount: " + PrivatePageCount + delimiter + 
						"ProcessId: " + ProcessId + delimiter + 
						"QuotaNonPagedPoolUsage: " + QuotaNonPagedPoolUsage + delimiter + 
						"QuotaPagedPoolUsage: " + QuotaPagedPoolUsage + delimiter + 
						"QuotaPeakNonPagedPoolUsage: " + QuotaPeakNonPagedPoolUsage + delimiter + 
						"QuotaPeakPagedPoolUsage: " + QuotaPeakPagedPoolUsage + delimiter + 
						"ReadOperationCount: " + ReadOperationCount + delimiter + 
						"ReadTransferCount: " + ReadTransferCount + delimiter + 
						"SessionId: " + SessionId + delimiter + 
						"Status: " + Status + delimiter + 
						"TerminationDate: " + TerminationDate + delimiter + 
						"ThreadCount: " + ThreadCount + delimiter + 
						"UserModeTime: " + UserModeTime + delimiter + 
						"VirtualSize: " + VirtualSize + delimiter + 
						"WindowsVersion: " + WindowsVersion + delimiter + 
						"WorkingSetSize: " + WorkingSetSize + delimiter + 
						"WriteOperationCount: " + WriteOperationCount + delimiter + 
						"WriteTransferCount: " + WriteTransferCount + delimiter + 
						get_netstat_line(include_netstat, netstat_starting_location); 

				
			}
			
			return 	process_name + delimiter + 
					PID   + delimiter + 
					ParentProcessId + delimiter +
					parent_process_name + delimiter +
					ExecutablePath + delimiter +
					CommandLine + delimiter +
					 
					
					/*"session_name: " + session_name + delimiter + 
					"session_number: " + session_number + delimiter + 
					"mem_usage: " + mem_usage + delimiter + 
					"status: " + status  + delimiter + 
					"user_name: " + user_name + delimiter + 
					"cpu_time: " + cpu_time + delimiter + 
					"window_title: " + window_title + delimiter + */
					
					this.running_state + delimiter +
					this.first_detection_time_text + delimiter +
					this.first_detection_time + delimiter + 
					this.last_detection_time_text + delimiter +
					this.last_detection_time + delimiter + 
					
					Node + delimiter + 
					Caption + delimiter + 						 
					CreationClassName + delimiter + 
					CreationDate + delimiter + 
					CSCreationClassName + delimiter + 
					CSName + delimiter + 
					Description + delimiter + 
					
					ExecutionState + delimiter + 
					Handle + delimiter + 
					HandleCount + delimiter + 
					InstallDate + delimiter + 
					KernelModeTime + delimiter + 
					MaximumWorkingSetSize + delimiter + 
					MinimumWorkingSetSize + delimiter + 
					Name + delimiter + 
					OSCreationClassName + delimiter + 
					OSName + delimiter + 
					OtherOperationCount + delimiter + 
					OtherTransferCount + delimiter + 
					PageFaults + delimiter + 
					PageFileUsage + delimiter + 						 
					PeakPageFileUsage + delimiter + 
					PeakVirtualSize + delimiter + 
					PeakWorkingSetSize + delimiter + 
					Priority + delimiter + 
					PrivatePageCount + delimiter + 
					ProcessId + delimiter + 
					QuotaNonPagedPoolUsage + delimiter + 
					QuotaPagedPoolUsage + delimiter + 
					QuotaPeakNonPagedPoolUsage + delimiter + 
					QuotaPeakPagedPoolUsage + delimiter + 
					ReadOperationCount + delimiter + 
					ReadTransferCount + delimiter + 
					SessionId + delimiter + 
					Status + delimiter + 
					TerminationDate + delimiter + 
					ThreadCount + delimiter + 
					UserModeTime + delimiter + 
					VirtualSize + delimiter + 
					WindowsVersion + delimiter + 
					WorkingSetSize + delimiter + 
					WriteOperationCount + delimiter + 
					WriteTransferCount + delimiter + 
					get_netstat_line(include_netstat, netstat_starting_location);  
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "toString", e);
		}
		
		str = "";
		return PID;
	}
	
	public String get_netstat_line(boolean include_netstat, String netstat_starting_location)
	{
		try
		{
			if(!include_netstat)
				return "";
			
			if(this.list_netstat == null  || this.list_netstat.isEmpty())
				return "";
			
			//sort netstat entries based on connection state
			try
			{
				Collections.sort(list_netstat, new Comparator<Node_Netstat>()
				{
					public int compare(Node_Netstat t1, Node_Netstat t2)
					{
						return t2.connection_state.compareToIgnoreCase(t1.connection_state);
					}						
					
				});
			}catch(Exception ee){}
			
			netstat_value = "";
			
			for(Node_Netstat netstat : this.list_netstat)
			{
				if(netstat == null)
					continue;
				
				netstat_value = netstat_value + netstat_starting_location + "[*] " + netstat.toString();
			}
			
			return netstat_value ;
		}
		
		catch(Exception e)
		{
			driver.eop(myClassName, "get_netstat_line", e);
		}
		
		return netstat_value;
	}
	
	public static boolean export_process_tree()
	{
		try
		{
			//ensure parent file exists
			File top_folder = new File("." + File.separator + Driver.NAME);
			
			File export = new File("." + File.separator + Driver.NAME + File.separator + "export");
			
			if(!export.exists() || !export.isDirectory())
				export.mkdirs();			
			
			//create tree file
			File fleTree = write_process_tree(export);
			
			if(fleTree != null && fleTree.exists())
			{
				driver.open_file(fleTree);
			}
			
			
			
			return true;	
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "export_process_tree", e);
		}
		
		return false;
	}
	
	private static File write_process_tree(File output_directory)
	{
		try
		{
			if(output_directory == null || !output_directory.exists() || !output_directory.isDirectory())
				output_directory = new File("./");
			
			String path = output_directory.getCanonicalPath().trim();
			
			if(!path.endsWith(File.separator))
				path = path + File.separator;
			
			//create the stream
			File fle = new File(path + "process_tree.txt");
			PrintWriter pwOut = new PrintWriter(new FileWriter(fle), true);
			
			print_process_tree(pwOut);
			
			pwOut.flush();
			pwOut.close();
			
			return fle;
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_process_tree", e);
		}
		
		return null;
	}
	
	
	public String get_netstat_data(String delimiter)
	{
		try
		{
			value = "process_name: " + process_name + delimiter;
			
			if(!CommandLine.trim().equals(""))
				value = value + "process_command_line: " + CommandLine + delimiter;
			
			if(!this.ExecutablePath.trim().equals(""))
				value = value + "process_executable_path: " + ExecutablePath + delimiter;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "get_netstat_data", e);
		}
		
		return value;
	}
	
	
	
	public static File export_process_table(boolean print_table_header, String delimiter, boolean open_file_upon_completion)
	{
		try
		{
			if(Node_Process.tree_process == null || Node_Process.tree_process.isEmpty())
				return null;
			
			//update parent nodes first
			update_node_parents();
			update_terminated_processes();
			
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
			File fle = new File(path + "process_table.txt");
			PrintWriter pwOut = new PrintWriter(new FileWriter(fle), true);
			
			
			LinkedList<Node_Process> list = new LinkedList<Node_Process>(Node_Process.tree_process.values());
			
			//
			//sort based on process name
			//
			try
			{
				Collections.sort(list, new Comparator<Node_Process>()
				{
					public int compare(Node_Process t1, Node_Process t2)
					{
						//if(t1.process_name != null && t2.process_name != null)
							return t1.process_name.compareToIgnoreCase(t2.process_name);
						
					}						
					
				});
			}catch(Exception ee){}
			
			//
			//print header
			//
			if(print_table_header)
				pwOut.println("process_name" + delimiter + 
						"PID" + delimiter + 
						"parent_PID" + delimiter +
						"parent_process_name" + delimiter +
						"ExecutablePath" + delimiter +
						"CommandLine" + delimiter +
						/*session_name"" + delimiter + 
						"session_number" + delimiter + 
						"mem_usage" + delimiter + 
						"status" + delimiter + 
						"user_name" + delimiter + 
						"cpu_time" + delimiter + 
						"window_title" + delimiter + */
						
						"Running State: " + delimiter +
						"First Detection Time: " + delimiter +
						"First Detection Time_millis: " + delimiter + 
						"Last Detection Time: " +  delimiter +
						"Last Detection Time_millis: " + delimiter + 
						
						"Node" + delimiter + 
						"Caption" + delimiter + 
						"CreationClassName" + delimiter + 
						"CreationDate" + delimiter + 
						"CSCreationClassName" + delimiter + 
						"CSName" + delimiter + 
						"Description" + delimiter + 
						"ExecutionState" + delimiter + 
						"Handle" + delimiter + 
						"HandleCount" + delimiter + 
						"InstallDate" + delimiter + 
						"KernelModeTime" + delimiter + 
						"MaximumWorkingSetSize" + delimiter + 
						"MinimumWorkingSetSize" + delimiter + 
						"Name" + delimiter + 
						"OSCreationClassName" + delimiter + 
						"OSName" + delimiter + 
						"OtherOperationCount" + delimiter + 
						"OtherTransferCount" + delimiter + 
						"PageFaults" + delimiter + 
						"PageFileUsage" + delimiter + 
						"PeakPageFileUsage" + delimiter + 
						"PeakVirtualSize" + delimiter + 
						"PeakWorkingSetSize" + delimiter + 
						"Priority" + delimiter + 
						"PrivatePageCount" + delimiter + 
						"ProcessId" + delimiter + 
						"QuotaNonPagedPoolUsage" + delimiter + 
						"QuotaPagedPoolUsage" + delimiter + 
						"QuotaPeakNonPagedPoolUsage" + delimiter + 
						"QuotaPeakPagedPoolUsage" + delimiter + 
						"ReadOperationCount" + delimiter + 
						"ReadTransferCount" + delimiter + 
						"SessionId" + delimiter + 
						"Status" + delimiter + 
						"TerminationDate" + delimiter + 
						"ThreadCount" + delimiter + 
						"UserModeTime" + delimiter + 
						"VirtualSize" + delimiter + 
						"WindowsVersion" + delimiter + 
						"WorkingSetSize" + delimiter + 
						"WriteOperationCount" + delimiter 	+ 
						"WriteTransferCount" 
						);
						
			
			//
			//print data
			//
			for(Node_Process node : list)
			{
				if(node == null)
					continue;
				
				pwOut.println(node.toString(delimiter, false, false, ""));
			}
			
			pwOut.flush();
			pwOut.close();
			
						
			
			if(open_file_upon_completion && fle != null && fle.exists())
			{
				driver.open_file(fle);
			}
			
			
			
			return fle;	
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "export_process_table", e);
		}
		
		return null;
	}
	
	
	public static boolean update_terminated_processes()
	{
		try
		{
			if(Node_Process.tree_process == null || Node_Process.tree_process.isEmpty())
				return false;
			
			current_time = System.currentTimeMillis();
			
			LinkedList<Node_Process> list = new LinkedList<Node_Process>(Node_Process.tree_process.values());
			
			for(Node_Process node : list)
			{
				if(node == null)
					continue;
						
				if(node.last_detection_time + 10000 < current_time)
				{
					if(!node.running_state.equalsIgnoreCase("terminated"))
					{
						node.running_state = "TERMINATED";
						update_required = true;
					}									
				}
			
			}//end for
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "update_terminated_processes", e);
		}
		
		return false;
	}
	
	
	public String [] get_jtable_row()
	{
		try
		{						
			set_parent_process();
			
			array[0] = process_name;
			array[1] = PID;
			array[2] = parent_PID;
			array[3] = parent_process_name;
			array[4] = ExecutablePath;
			array[5] = CommandLine;
			array[6] = this.running_state ;
			array[7] = this.first_detection_time_text ;
			array[8] = ""+this.first_detection_time ;
			array[9] = this.last_detection_time_text ;
			array[10] = ""+this.last_detection_time ;
			array[11] = Node;
			array[12] = Caption;
			array[13] = CreationClassName;
			array[14] = CreationDate;
			array[15] = CSCreationClassName;
			array[16] = CSName;
			array[17] = Description;
			array[18] = ExecutionState;
			array[19] = Handle;
			array[20] = HandleCount;
			array[21] = InstallDate;
			array[22] = KernelModeTime;
			array[23] = MaximumWorkingSetSize;
			array[24] = MinimumWorkingSetSize;
			array[25] = Name;
			array[26] = OSCreationClassName;
			array[27] = OSName;
			array[28] = OtherOperationCount;
			array[29] = OtherTransferCount;
			array[30] = PageFaults;
			array[31] = PageFileUsage;
			array[32] = PeakPageFileUsage;
			array[33] = PeakVirtualSize;
			array[34] = PeakWorkingSetSize;
			array[35] = Priority;
			array[36] = PrivatePageCount;
			array[37] = ProcessId;
			array[38] = QuotaNonPagedPoolUsage;
			array[39] = QuotaPagedPoolUsage;
			array[40] = QuotaPeakNonPagedPoolUsage;
			array[41] = QuotaPeakPagedPoolUsage;
			array[42] = ReadOperationCount;
			array[43] = ReadTransferCount;
			array[44] = SessionId;
			array[45] = Status;
			array[46] = TerminationDate;
			array[47] = ThreadCount;
			array[48] = UserModeTime;
			array[49] = VirtualSize;
			array[50] = WindowsVersion;
			array[51] = WorkingSetSize;
			array[52] = WriteOperationCount;
			array[53] = WriteTransferCount;
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "get_jtable_row", e);
		}
		
		return array;
	}
	
	
	public static LinkedList<Node_Map_Details> get_linked_list_of_map_details_from_each_node(boolean include_map_header, boolean include_terminated_processes_as_well)
	{
		try
		{
			if(Node_Process.tree_process == null || tree_process.isEmpty())
			{
				return null;
			}
			
			try	{	list_map_details.clear();} catch(Exception e){list_map_details = new LinkedList<Node_Map_Details>();}
			
			Node_Map_Details map_details = null;
			
			for(Node_Process node : Node_Process.tree_process.values())
			{
				if(node.list_netstat == null || node.list_netstat.isEmpty())
					continue;				
				
				for(Node_Netstat netstat : node.list_netstat)
				{
					if(netstat.geo == null)
					{
						if(GEO_Location.TREE_GEO_LOCATION.containsKey(netstat.foreign_address))
							netstat.geo = GEO_Location.TREE_GEO_LOCATION.get(netstat.foreign_address);
					}
					
					if(netstat.geo == null)
						continue;
					
					//ensure the parent is updated
					if(netstat.node_process == null)
					{
						netstat.node_process = node;
						netstat.parent_process_name = node.Name;
					}
					
					//valid geo here...
					if(!include_terminated_processes_as_well && node.running_state.equalsIgnoreCase("terminated"))
						continue;
					
					map_details = netstat.get_map_node(include_map_header);
					
					if(!list_map_details.contains(map_details))
						list_map_details.add(map_details);
				}
												
				
			}						
			
			return list_map_details;
		}
		catch(Exception e)
		{
			System.out.println("Check through get_linked_list_of_map_details_from_each_node mtd in class: " + myClassName);
		}
		
		return null;
	}
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
}
