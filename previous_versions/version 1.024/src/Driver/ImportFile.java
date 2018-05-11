/**
 * @author Solomon Sonya
 */
package Driver;

import java.util.*;
import java.awt.event.*;
import javax.swing.*;
import javax.swing.Timer;

import Parser.Parser;
import Parser.ParserServerSocket;
import Sensor.SensorServerSocket;

import java.io.*;


public class ImportFile extends Thread implements Runnable, ActionListener
{
	public static final String myClassName = "ImportFile";
	public static volatile Driver driver = new Driver();
	public static final String VERSION_ImportFile = "1.000";

	public File fle = null;
	public volatile String line = "";
	public volatile String lower = "";
	public BufferedReader brIn = null;
	
	Timer tmrReadFile = null;
	public volatile boolean handle_interrupt = true;
	public volatile long num_lines = 0;
	
	public volatile int index = 0;
	
	public ImportFile(File file)
	{
		try
		{
			fle = file;
			
			if(fle == null || !fle.exists())
				fle = driver.querySelectFile(true, "Please select file to import", JFileChooser.FILES_ONLY, false, false);
			
			if(fle != null && fle.exists())			
			{
				//ensure parsers are ready!
				
				//start parser threads
				for(int i = 0; i < ParserServerSocket.NUM_PARSER_THREADS && Parser.list_parsers.size() < ParserServerSocket.NUM_PARSER_THREADS; i++)
				{
					Parser.list_parsers.add(new Parser());
				}
				
				this.start();
			}
			else
				driver.directive("PUNT! File appears to be invalid or no longer exists...");
			
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
			if(fle != null && fle.exists())	
			{
				StandardInListener.stop = false;
				
				driver.directive("Attempting to open file --> " + fle.getCanonicalPath());
				brIn = new BufferedReader(new FileReader(fle));
				
				//configure system as necessary				
				if(Parser.list_parsers == null || Parser.list_parsers.size() < 1)
				{				
					//ensure parsers are started
					ParserServerSocket svrskt_parser = new ParserServerSocket(SensorServerSocket.DEFAULT_PARSER_PORT);
				}
				
				//initiate timer
				tmrReadFile = new Timer(30, this);
				tmrReadFile.start();
			}
		}
		catch(Exception e)
		{
			//driver.eop(myClassName, "run", e);
			driver.directive("PUNT!!! I was unable to initialize read actions on file -->" + fle);
		}
	}
	
	public void actionPerformed(ActionEvent ae)
	{
		try
		{
			if(ae.getSource() == this.tmrReadFile && this.handle_interrupt)
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
			if(!handle_interrupt)
				return false;
			
			handle_interrupt = false;
			
			//read next line and process
			line = brIn.readLine();
			
			//determine if we're finished reading file
			if(line == null)
			{
				//notify
				driver.directive("\nComplete! Num Lines Read: [" + num_lines + "] on file --> " + fle.getCanonicalPath());
				
				//close file
				try	{	brIn.close();} catch(Exception e){}
				
				//stop timer
				try	{	this.tmrReadFile.stop(); } catch(Exception e){}
				
				//update jtble if applicable
				StandardInListener.update_jtbl_Nodes(true);
				
				//leave semaphore lock				
				return true;
			}
			
			lower = line.toLowerCase().trim();
			
			//
			//check on the stop command
			//
			if(StandardInListener.stop)
			{
				//notify
				driver.directive("\nSTOP COMMAND RECEIVED. Halting read action. Num Lines Read: [" + num_lines + "] on file --> " + fle.getCanonicalPath());
				
				//close file
				try	{	brIn.close();} catch(Exception e){}
				
				//stop timer
				try	{	this.tmrReadFile.stop(); } catch(Exception e){}
				
				//update jtble if applicable
				StandardInListener.update_jtbl_Nodes(true);
				
				//leave semaphore lock				
				return true;
			}
			
			//update			
			++num_lines;
			
			//skip blank lines
			if(line.trim().equals(""))
			{
				handle_interrupt = true;
				return true;
			}
			
			//skip header lines
			if(lower.contains("src_ip") && lower.contains("src_mac") || lower.contains("successfully connected to"))
			{
				handle_interrupt = true;
				return true;
			}
			
			if(lower.startsWith("process"))
				line = line.substring(7);
			
			//process line
			process_line(line, false);
			
			
			//return
			handle_interrupt = true;
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "process_interrupt", e);
		}
		
		//punt!
		handle_interrupt = true;
		return false;
	}
	
	public boolean process_line(String line, boolean verbose)
	{
		try
		{
			if(Parser.list_parsers != null && Parser.list_parsers.size() > 0)
			{
				Parser.list_parsers.get(index++).parse(line);
				
				if(index % Parser.list_parsers.size() == 0)
					index = 0;
				
				if(num_lines %100 == 0)
				{
					driver.sp(".");
					
					//update jtble if applicable
					StandardInListener.update_jtbl_Nodes(true);
				}
				
				if(verbose)
					driver.sop(line);
			}
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "process_line", e);;
		}
		
		return false;
	}
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
}
