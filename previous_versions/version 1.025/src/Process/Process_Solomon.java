/**
 * There are times where we wish to execute multiple commands within the same process. 
 * For instance, forensics, if we want to orbit the tasklist and routinely grab the data that is present, 
 * Just using the Runtime.exec command creates a separate cmd.exe / conhost.exe on Windows machines...
 * Running that for a while is problematic as it will fill the process table with lots of unneccesary data.
 * 
 * To alleviate this issue, we have created our own process class that handles the instantiation of a process builder and a process
 * Then we send commands to this process, and the error streams and input streams are gobbled and handled separately by the 
 * StreamGobbler threads to allow multi-threaded execution in parallel
 * 
 * @author Solomon Sonya
 */

package Process;

import Driver.*;

import java.io.*;

public class Process_Solomon extends Thread implements Runnable
{
	public static volatile Driver driver = new Driver();
	public static final String myClassName = "Process_Solomon";
	public static volatile boolean verbose = false;
	
	public volatile Process process = null;		
	public volatile ProcessBuilder process_builder = null;
	public volatile StreamGobbler stream_gobbler = null;
	public volatile BufferedWriter buffered_writer = null;
	
	//specfiy what action to execute when we receive input across the reader stream (this is to pass on  to the gobblers)
	public static final int execution_action_PRINT_TO_SOP = 0;
	
	/**for /F "tokens=1-5 delims= " %A in ('netstat -ano') do echo %A,%B,%C,%D,%E*/
	public static final int execution_action_NETSTAT = 1;
	
	/**tasklist /v /fo csv*/
	public static final int execution_action_TASKLIST = 2;
	
	/**wmic process get /format:csv*/
	public static final int execution_action_WMIC_PROCESS = 3;
	
	/**Time Stamp for the last time input was received - we'll use this to deflect a new interrupt if we're still processing an input line - updated in stream gobblers*/
	public static volatile long last_process_time_stamp = 0;
	
	public int myExecution_Action = 0;
	
	public Process_Solomon(int execution_action)
	{
		try
		{
			//speciy how to handle the input once received from standard in
			this.myExecution_Action = execution_action;
			
			init();
			
			this.start();
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "Constructor - 1", e);
		}
	}
	
	/**do this to latch on to a separate process than cmd.exe or bin/bash. Call the update to execute the same cmd again*/
	public Process_Solomon(String shell, int execution_action)
	{
		try
		{
			//speciy how to handle the input once received from standard in
			this.myExecution_Action = execution_action;
			
			//attach to cmd and conhost process		
			process_builder = new ProcessBuilder(shell);
						
			process = process_builder.start();
			
			//create gobblers to read any data that is received
			stream_gobbler = new StreamGobbler(process, myExecution_Action, true, this);
			
			//create our printwriter
			buffered_writer = new BufferedWriter(new OutputStreamWriter(this.process.getOutputStream()));
			
			this.start();
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "Constructor - 1", e);
		}
	}
	
	public boolean init()
	{
		try
		{		
			//cleanup from previous process if applicable
			if(process != null)
				try	{	process.destroy();	}	catch(Exception e){}
			
			if(buffered_writer != null)
				try	{	buffered_writer.close();}catch(Exception e){}
			
			//attach to cmd and conhost process		
			if(driver.isWindows)
				process_builder = new ProcessBuilder("cmd.exe");
			
			else if(driver.isLinux)
				process_builder = new ProcessBuilder("/bin/bash");
								
						
			//instantiate new process
			process = process_builder.start();
			
			//create gobblers to read any data that is received
			stream_gobbler = new StreamGobbler(process, myExecution_Action, true, this);
			
			//create our printwriter						
			buffered_writer = new BufferedWriter(new OutputStreamWriter(this.process.getOutputStream()));
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "init", e);
		}
		
		return false;
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
	
	public boolean exec(String cmd)
	{
		try
		{
			//deflect if we're still processing an input line
			/*if(System.currentTimeMillis() < last_process_time_stamp + 300)
			{
				driver.directive("deflecting");
				return true;
			}*/
			
			if(verbose)
				driver.sop("Executing -->" + cmd);
			
			//
			//EXECUTE
			//
			buffered_writer.write(cmd);
			buffered_writer.newLine();
			buffered_writer.flush();
			
			//
			//UPDATE PROCESS TIME
			//
			last_process_time_stamp = System.currentTimeMillis();//; + 3000;
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "exec", e);
		}
		
		return false;
	}
	
	
	public boolean update(String cmd)
	{
		try
		{
						
			if(verbose)
				driver.sop("Executing -->" + cmd);
			
			//
			//EXECUTE
			//
			buffered_writer.write(cmd);
			buffered_writer.newLine();
			buffered_writer.flush();
			
			//
			//UPDATE PROCESS TIME
			//
			last_process_time_stamp = System.currentTimeMillis();//; + 3000;
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "update", e);
		}
		
		return false;
	}
	
	
	
	
	
	
	
	
	
	
	
	

}
