/**
 * @author Solomon Sonya
 */

package Process;
/**
 * The purpose of this class is to continuously read input received across a reader stream
 * 
 * For example, when we create a process and wish to run multiple commands across the same process, 
 * then we require a separate reader thread to read the input received across the stream and process it somehwere else
 * @author Solomon Sonya
 *
 */

import Driver.*;
import Sensor.*;
import Worker.*;
import java.io.*;
import java.util.LinkedList;


public class StreamGobbler extends Thread implements Runnable
{
	public static final String myClassName = "StreamGobbler";
	public static volatile Driver driver = new Driver();
	
	public volatile BufferedReader brIn = null;
	public volatile boolean is_standard_input_reader = false;
	public volatile boolean is_standard_error_reader = false;
	
	public int myExecution_Action = 0;
	
	public volatile Process parent = null;
	public volatile Process_Solomon parent_solomon = null;
	
	public volatile String [] array_TASKLIST = null;
	public volatile String [] array_NETSTAT = null;
	public volatile String [] array_WMIC_PROCESS = null;
	
	public volatile Node_Process node = null;
	
	public volatile String 	process_name = "",
							PID = "",
							session_name = "",
							session_number = "",
							mem_usage = "",
							status = "",
							user_name = "",
							cpu_time = "",
							window_title = "";

	public volatile String 	protocol = "",
							local_address_full = "",
							local_address = "",
							local_port = "",
							foreign_address_full = "",
							foreign_address = "",
							foreign_address_port = "",
							connection_state = "";
	
	public volatile String key = "";
	
	/**determine if we will try to re-instantiate the process in case it crashes or the cmd.exe terminal is closed*/
	public boolean resuscitate = true;
	
	public StreamGobbler(Process p, int execution_action, boolean resuscitate_process, Process_Solomon par_solomon)
	{
		try
		{
			resuscitate = resuscitate_process;
			parent_solomon = par_solomon;
			
			//use this to instantiate separate threads for the standard output and error streams
			if(p != null)
			{
				parent = p;
				
				
				//speciy how to handle the input once received from standard in
				this.myExecution_Action = execution_action;
				
				//instantiate the readers
				BufferedReader brIn = new BufferedReader(new InputStreamReader(p.getInputStream()));
				BufferedReader brError = new BufferedReader(new InputStreamReader(p.getErrorStream()));
				
				//pass the readers to the threads to gobble
				StreamGobbler gobbler_in = new StreamGobbler(parent, brIn, myExecution_Action, true, par_solomon);
				StreamGobbler gobbler_error = new StreamGobbler(parent, brError, myExecution_Action, false, par_solomon);
			}
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "Constructor - 1");
		}
		
	}
	
	
	public StreamGobbler(Process par, BufferedReader br, int execution_action, boolean this_is_standard_input_reader, Process_Solomon par_solomon)
	{
		try
		{
			parent = par;
			parent_solomon = par_solomon;
			
			//speciy how to handle the input once received from standard in
			this.myExecution_Action = execution_action;
			
			brIn = br;
			is_standard_input_reader = this_is_standard_input_reader;
			is_standard_error_reader = !this_is_standard_input_reader;
			
			this.start();			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "Constructor - 1");
		}
		
	}

	
	public void run()
	{
		try
		{
			String line = "";
			String lower = "";
			
			while((line = brIn.readLine()) != null)
			{
				if(line.trim().equals(""))
					continue;
				
				//
				//update process time
				//
				Process_Solomon.last_process_time_stamp = System.currentTimeMillis();
								
				//
				//lower
				//
				lower = line.toLowerCase();
				
				
				//
				//EXECUTION ACTION
				//
				switch(this.myExecution_Action)
				{
					case Process_Solomon.execution_action_PRINT_TO_SOP:
					{
						driver.directive(line);
						break;
					}
					
					case Process_Solomon.execution_action_TASKLIST:
					{
						process_execution_action_TASKLIST(line, lower);
						break;
					}

					case Process_Solomon.execution_action_NETSTAT:
					{
						process_execution_action_NETSTAT(line, lower);
						break;
					}
					
					case Process_Solomon.execution_action_WMIC_PROCESS:
					{
						process_execution_action_WMIC_PROCESS(line, lower);
						break;
					}
					
					default:
					{
						driver.directive(line);
						break;
					}
					
				}
				
				
			}
			
			driver.directive("\nReader stream closed for thread: " + this.getId());
			
			if(resuscitate && parent_solomon != null && is_standard_input_reader)
			{
				driver.directive("Attempting to resuscitate process...");
				parent_solomon.init();
			}
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "run", e);
		}
	}
	
	//////////////////////////////////////////////////////////
	/////////////////////////////////////////////////////////
	////////////////////////////////////////////////////////
	///////////////////////////////////////////////////////
	/**
	 * tasklist /v /fo csv
	 * 
	 * @param line
	 * @param lower
	 * @return
	 */
	public boolean process_execution_action_TASKLIST(String line, String lower)
	{
		try
		{
			if(line == null || lower == null)
				return false;
			
			line = line.trim();
			lower = lower.trim();
			
			if(line.trim().equals("") || lower.trim().equals(""))
				return false;
			
			//
			//dismiss repeated lines
			//
			if(lower.contains("echo"))
				return false;
			
			//
			//normalize
			//
			line = line.replaceAll("\"", "");
			
			//
			//normalize commas and spaces for better tokenization such that 2 blank adjacent commas (e.g. ,,) will not be treated as a single entry (hopefully!)
			//
			line = line.replaceAll(",",  ", ");
			
			//tasklist /v /fo csv
			//"Image Name","PID","Session Name","Session#","Mem Usage","Status","User Name","CPU Time","Window Title"
			//Image Name,PID,Session Name,Session#,Mem Usage,Status,User Name,CPU Time,Window Title
			//"System Idle Process","0","Services","0","24 K","Unknown","NT AUTHORITY\SYSTEM","136:28:07","N/A"
			//"System","4","Services","0","2,016 K","Unknown","N/A","0:16:03","N/A"
			
			array_TASKLIST = line.split(",");
			
			if(array_TASKLIST == null || array_TASKLIST.length < 1)
				return false;
			
			//note, there are times where the value [Mem Usage] contains a comma for 2,016K and other times, no comma e.g. 24K
			//process below based on length of the array
			
			//length without extra comma == 9
			
			
			if(array_TASKLIST.length == 9)
			{
				process_name = array_TASKLIST[0].trim();
				PID = array_TASKLIST[1].trim();
				session_name = array_TASKLIST[2].trim();
				session_number = array_TASKLIST[3].trim();
				mem_usage = array_TASKLIST[4].trim();
				status = array_TASKLIST[5].trim();
				user_name = array_TASKLIST[6].trim();
				cpu_time = array_TASKLIST[7].trim();
				window_title = array_TASKLIST[8].trim();
			}
			
			else if(array_TASKLIST.length == 10)
			{
				process_name = array_TASKLIST[0].trim();
				PID = array_TASKLIST[1].trim();
				session_name = array_TASKLIST[2].trim();
				session_number = array_TASKLIST[3].trim();
				mem_usage = array_TASKLIST[4].trim() + "" + array_TASKLIST[5].trim();
				status = array_TASKLIST[6].trim();
				user_name = array_TASKLIST[7].trim();
				cpu_time = array_TASKLIST[8].trim();
				window_title = array_TASKLIST[9].trim();
			}
			
			 
			//
			//process the node
			//
			
			Node_Process node = null;
			
			if(Node_Process.tree_process.containsKey(PID))
				node = Node_Process.tree_process.get(PID);
			
			if(node == null)
			{
				node = new Node_Process(PID, process_name);
				node.process_name = process_name;
			}
			
			if(node.process_name.trim().equals(""))
				node.process_name = process_name;
			
			node.session_name = session_name;
			node.session_number = session_number;
			node.mem_usage = mem_usage;
			node.status = status;
			node.Status = status;
			node.user_name = user_name;
			node.cpu_time = cpu_time;
			node.window_title = window_title;
				
			
			
			 
			 
			 
			 
			 /*
			driver.directive("TASKLIST -->\t" + line);
			driver.directive("process_name -->" + process_name);
			driver.directive("PID -->" + PID);
			driver.directive("session_name -->" + session_name);
			driver.directive("session_number -->" + session_number);
			driver.directive("mem_usage -->" + mem_usage);
			driver.directive("status -->" + status);
			driver.directive("user_name -->" + user_name);
			driver.directive("cpu_time -->" + cpu_time);
			driver.directive("window_title -->" + window_title);
			driver.directive("\n==============\n");*/
			
			
			
			
			
			
			return true;
		}
		
		catch(Exception e)
		{
			driver.eop(myClassName, "process_execution_action_TASKLIST", e);
		}
		
		return false;
	}
	
	//////////////////////////////////////////////////////////
	/////////////////////////////////////////////////////////
	////////////////////////////////////////////////////////
	///////////////////////////////////////////////////////
	/**
	 * for /F "tokens=1-5 delims= " %A in ('netstat -ano') do echo %A,%B,%C,%D,%E
	 * 
	 * @param line
	 * @param lower
	 * @return
	 */
	public boolean process_execution_action_NETSTAT(String line, String lower)
	{
		try
		{
			if(line == null || lower == null)
				return false;
			
			line = line.trim();
			lower = lower.trim();
			
			if(line.trim().equals("") || lower.trim().equals(""))
				return false;
			
			//
			//dismiss irrelevant lines
			//
			if(!(lower.startsWith("tcp") || lower.startsWith("udp")))
			{
				return false;
			}
					
			if(lower.contains("echo"))
				return false;
									
			//
			//normalize
			//
			//line = line.replaceAll("\"", "");
			
			//
			//normalize commas and spaces for better tokenization such that 2 blank adjacent commas (e.g. ,,) will not be treated as a single entry (hopefully!)
			//
			line = line.replaceAll(",",  ", ");
			
			
			//
			//tokenize
			//
			array_NETSTAT = line.split(",");
			
			//expected length is 46. If not, reject
			if(array_NETSTAT == null || array_NETSTAT.length < 2)
				return false;
			
			//Proto,Local,Address,Foreign,Address,State,PID
			//TCP,0.0.0.0:135,0.0.0.0:0,LISTENING,800
			//TCP,192.168.0.100:1045,108.177.103.188:5228,ESTABLISHED,1752
			//TCP,192.168.0.100:1429,74.125.3.42:443,TIME_WAIT,0 
			//UDP,0.0.0.0:500,*:*,396, 
			//UDP,[fe80::b0af:91ee:612c:ee00%16]:1900,*:*,1444,
			
			protocol 					= array_NETSTAT[0].trim();
			
			if(protocol.trim().equalsIgnoreCase("tcp"))
			{
				local_address_full 			= array_NETSTAT[1].trim();
				foreign_address_full 		= array_NETSTAT[2].trim();
				connection_state			= array_NETSTAT[3].trim();
				PID							= array_NETSTAT[4].trim();
			}
			else if(protocol.trim().equalsIgnoreCase("udp"))
			{
				local_address_full 			= array_NETSTAT[1].trim();
				foreign_address_full 		= array_NETSTAT[2].trim();
				PID							= array_NETSTAT[3].trim();
				
				//set connection state for UDP to be standard with our TCP data
				if(foreign_address_full.equalsIgnoreCase("*:*"))
					connection_state = "LISTENING";
				else
					connection_state = "ESTABLISHED";
			}
			
			//key = local_address_full + "_" + connection_state + "_" + foreign_address_full + "_" + PID;
			key = local_address_full + "_" + foreign_address_full + "_" + PID;
			
			//
			//dismiss if connection state == TIME_WAIT and PID == 0; here, a connection was closed, netstat reports PID as 0 which incorrectly
			//attributes this activity to the System Idle Process on windows machines
			//
			if(connection_state.toUpperCase().contains("TIME_WAIT") && PID.equals("0"))
				return false;
			
			//
			//Check if new node is required
			//
			Node_Netstat node = null;
			
			if(Node_Netstat.tree_netstat.containsKey(key))
				node = Node_Netstat.tree_netstat.get(key);
			
			if(node == null)
				node = new Node_Netstat(PID, protocol, local_address_full, foreign_address_full, connection_state);
			else
			{
				node.connection_state = connection_state;
				node.last_detection_time = System.currentTimeMillis();
				node.last_detection_time_text 	= driver.get_time_stamp_hyphenated();
			}

			//
			//check to update process based on PID
			//
			if(node.node_process == null && Node_Process.tree_process.containsKey(PID))
			{
				Node_Process process = Node_Process.tree_process.get(PID);
				
				if(process != null)
				{
					//link the process to netstat object
					node.node_process = process;
					
					//link netstat object to the process
					if(process.list_netstat == null)
						process.list_netstat = new LinkedList<Node_Netstat>();
						
					if(!process.list_netstat.contains(node))
						process.list_netstat.add(node);
				}
			}
			
			return true;
		}
		
		catch(Exception e)
		{
			driver.eop(myClassName, "process_execution_action_NETSTAT", e);
		}
		
		return false;
	}
	
	
	
	//////////////////////////////////////////////////////////
	/////////////////////////////////////////////////////////
	////////////////////////////////////////////////////////
	///////////////////////////////////////////////////////
	/**
	 * wmic process get /format:csv
	 * 
	 * @param line
	 * @param lower
	 * @return
	 */
	public boolean process_execution_action_WMIC_PROCESS(String line, String lower)
	{
		try
		{
			if(line == null || lower == null)
				return false;
			
			line = line.trim();
			lower = lower.trim();
			
			if(line.trim().equals("") || lower.trim().equals(""))
				return false;
			
			if(lower.startsWith("node,caption,commandline,creationclassname,creationdate"))
				return true;
			
			//
			//normalize
			//
			//line = line.replaceAll("\"", "");
			
			//
			//normalize commas and spaces for better tokenization such that 2 blank adjacent commas (e.g. ,,) will not be treated as a single entry (hopefully!)
			//
			line = line.replaceAll(",",  ", ");
			
			//
			//tokenize
			//
			array_WMIC_PROCESS = line.split(",");
			
			//expected length is 46. If not, reject
			if(array_WMIC_PROCESS == null || array_WMIC_PROCESS.length < 2 || array_WMIC_PROCESS.length > 46)
				return false;
			
			//Node,Caption,CommandLine,CreationClassName,CreationDate,CSCreationClassName,CSName,Description,ExecutablePath,ExecutionState,Handle,HandleCount,InstallDate,KernelModeTime,MaximumWorkingSetSize,MinimumWorkingSetSize,Name,OSCreationClassName,OSName,OtherOperationCount,OtherTransferCount,PageFaults,PageFileUsage,ParentProcessId,PeakPageFileUsage,PeakVirtualSize,PeakWorkingSetSize,Priority,PrivatePageCount,ProcessId,QuotaNonPagedPoolUsage,QuotaPagedPoolUsage,QuotaPeakNonPagedPoolUsage,QuotaPeakPagedPoolUsage,ReadOperationCount,ReadTransferCount,SessionId,Status,TerminationDate,ThreadCount,UserModeTime,VirtualSize,WindowsVersion,WorkingSetSize,WriteOperationCount,WriteTransferCount
			//Size: 46  BLACK_BEAST, cmd.exe, cmd.exe, Win32_Process, 20180330025907.621907-420, Win32_ComputerSystem, BLACK_BEAST, cmd.exe, C:\Windows\system32\cmd.exe, , 8608, 40, , 156001, 1380, 200, cmd.exe, Win32_OperatingSystem, Microsoft Windows 7 Enterprise N |C:\Windows|\Device\Harddisk0\Partition2, 64, 1238, 1344, 3588, 8664, 3588, 46825472, 5244, 8, 3674112, 8608, 6, 112, 7, 112, 2, 12356, 1, , , 1, 0, 46825472, 6.1.7601, 5369856, 6, 167
			
			//handle == PID
			PID = array_WMIC_PROCESS[10].trim();
			this.process_name  = array_WMIC_PROCESS[7].trim(); 
			
						
			//
			//process the node
			//
			
			Node_Process node = null;
			
			if(Node_Process.tree_process.containsKey(PID))
				node = Node_Process.tree_process.get(PID);
			
			if(node == null)
			{
				node = new Node_Process(PID, process_name);
				node.process_name = process_name;				
			}
			
			if(node.process_name.trim().equals(""))
				node.process_name = process_name;
			
			//
			//set data
			//
			node.last_detection_time 		= System.currentTimeMillis();
			node.last_detection_time_text 	= driver.get_time_stamp_hyphenated();
			node.running_state = "RUNNING";
			
			node.Node 						= array_WMIC_PROCESS[0].trim(); 
			node.Caption 					= array_WMIC_PROCESS[1].trim(); 
			node.CommandLine 				= array_WMIC_PROCESS[2].trim(); 
			node.CreationClassName 			= array_WMIC_PROCESS[3].trim(); 
			node.CreationDate 				= array_WMIC_PROCESS[4].trim(); 
			node.CSCreationClassName 		= array_WMIC_PROCESS[5].trim(); 
			node.CSName 					= array_WMIC_PROCESS[6].trim(); 
			node.Description 				= array_WMIC_PROCESS[7].trim(); 
			node.ExecutablePath 			= array_WMIC_PROCESS[8].trim(); 
			node.ExecutionState 			= array_WMIC_PROCESS[9].trim(); 
			node.Handle 					= array_WMIC_PROCESS[10].trim(); 
			node.HandleCount 				= array_WMIC_PROCESS[11].trim(); 
			node.InstallDate 				= array_WMIC_PROCESS[12].trim(); 
			node.KernelModeTime 			= array_WMIC_PROCESS[13].trim(); 
			node.MaximumWorkingSetSize 		= array_WMIC_PROCESS[14].trim(); 
			node.MinimumWorkingSetSize 		= array_WMIC_PROCESS[15].trim(); 
			node.Name 						= array_WMIC_PROCESS[16].trim(); 
			node.OSCreationClassName 		= array_WMIC_PROCESS[17].trim(); 
			node.OSName 					= array_WMIC_PROCESS[18].trim(); 
			node.OtherOperationCount 		= array_WMIC_PROCESS[19].trim(); 
			node.OtherTransferCount 		= array_WMIC_PROCESS[20].trim(); 
			node.PageFaults 				= array_WMIC_PROCESS[21].trim(); 
			node.PageFileUsage 				= array_WMIC_PROCESS[22].trim(); 
			node.ParentProcessId 			= array_WMIC_PROCESS[23].trim(); 
			node.parent_PID = node.ParentProcessId;
			node.PeakPageFileUsage 			= array_WMIC_PROCESS[24].trim(); 
			node.PeakVirtualSize 			= array_WMIC_PROCESS[25].trim(); 
			node.PeakWorkingSetSize 		= array_WMIC_PROCESS[26].trim(); 
			node.Priority 					= array_WMIC_PROCESS[27].trim(); 
			node.PrivatePageCount 			= array_WMIC_PROCESS[28].trim(); 
			node.ProcessId 					= array_WMIC_PROCESS[29].trim(); 
			node.QuotaNonPagedPoolUsage 	= array_WMIC_PROCESS[30].trim(); 
			node.QuotaPagedPoolUsage 		= array_WMIC_PROCESS[31].trim(); 
			node.QuotaPeakNonPagedPoolUsage = array_WMIC_PROCESS[32].trim(); 
			node.QuotaPeakPagedPoolUsage 	= array_WMIC_PROCESS[33].trim(); 
			node.ReadOperationCount 		= array_WMIC_PROCESS[34].trim(); 
			node.ReadTransferCount 			= array_WMIC_PROCESS[35].trim(); 
			node.SessionId 					= array_WMIC_PROCESS[36].trim(); 
			node.Status 					= array_WMIC_PROCESS[37].trim(); 
			node.TerminationDate 			= array_WMIC_PROCESS[38].trim(); 
			node.ThreadCount 				= array_WMIC_PROCESS[39].trim(); 
			node.UserModeTime 				= array_WMIC_PROCESS[40].trim(); 
			node.VirtualSize 				= array_WMIC_PROCESS[41].trim(); 
			node.WindowsVersion 			= array_WMIC_PROCESS[42].trim(); 
			node.WorkingSetSize 			= array_WMIC_PROCESS[43].trim(); 
			node.WriteOperationCount 		= array_WMIC_PROCESS[44].trim(); 
			node.WriteTransferCount 		= array_WMIC_PROCESS[45].trim();
			
			/////////////////////////////////////////////////
			//
			// REMOVE DIAGNOSTIC PROCESSES 
			//
			////////////////////////////////////////////////
			
			//
			//remove processes created by this program (e.g. if javaw.exe PID == 4388, then do not include processes that have PID 4388 as the parent
			//I hope to fix this later by having a better way to iterate through flink and blink in the actual process execution blocks, 
			//but for now, I'll use native programs to iterate through these for me
			//
			try
			{
				//
				//first check if there are any new parent PIDs to add to the ignore list
				//
				if(node.ParentProcessId.equals(driver.PID))
				{
					//check if there are new PID's to add. i.e. all PID's started by the main parent (javaw.exe) as well as all offspring (e.g. cmd.exe, conhost.exe, wmic.exe, tasklist.exe, etc) should not be included in the main list
					if(!Node_Process.list_PID_TO_IGNORE.contains(node.PID))
						Node_Process.list_PID_TO_IGNORE.add(node.PID);//we wish not to add the parent, so do not add the offspring either
				}
				
				//
				//now check if there are any PIDs to remove from list
				//
				if(Node_Process.list_PID_TO_IGNORE.contains(node.ParentProcessId) || Node_Process.list_PID_TO_IGNORE.contains(node.PID))
				{
					if(Node_Process.tree_process.containsKey(node.PID))
					{
						//if we do not wish to store the parent process, then we should not store any offspring by the parent either
						try
						{
							Node_Process.tree_process.remove(node.PID);
							Node_Process.tree_process.remove(node);
						}
						catch(Exception e){}
						
					}
					
					//
					//check parent processes as well
					//
					if(Node_Process.tree_parent_process.containsKey(node.PID))
					{
						try
						{
							Node_Process.tree_parent_process.remove(node.PID);
							Node_Process.tree_parent_process.remove(node);
						}
						catch(Exception e){}						
					}				
					
				}
				
				
						
			}
			catch(Exception ee){}
			
			
			/////////////////////////////////////////////////
			//
			// UPDATE PARENT NODES 
			//
			////////////////////////////////////////////////
			if(node.parent_process == null && Node_Process.tree_process.containsValue(node))
				node.set_parent_process();
			
			
			//Node_Process.update_required = true;
			
			return true;
		}
		
		catch(Exception e)
		{
			driver.eop(myClassName, "process_execution_action_WMIC_PROCESS", e);
		}
		
		return false;
	}
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	

}
