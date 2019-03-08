package Files;

import java.io.*;
import java.util.*;

import Driver.Driver;

import java.awt.event.*;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.awt.event.*;

public class File_Orbiter extends Thread implements Runnable, ActionListener 
{
	public static final String myClassName = "File_Orbiter";
	public static volatile Driver driver = new Driver();
	
	public static volatile boolean data_table_updated = false;
	
	public static volatile boolean ORBITER_ENABLED = true;
	public volatile boolean process_interrupt = true;
	public static volatile javax.swing.Timer tmr_orbiter = null;
	public static volatile int INTERRUPT_MILLIS = 300000;
	
	public volatile LinkedList<File> list_files = new LinkedList<File>();
	public static final File fleC = new File("C:\\");
	public static final String[] arrFileExtension = new String[] {	".bat", ".exe", ".bin", ".cmd", ".com", ".inf", ".lnk", ".msc", ".msi", ".msp", ".reg", 
																	".paf", ".vb", ".vbs", ".vbe", ".ws", ".wsf", ".wsh", ".jar", ".zip", ".7zip"};
	
	public File_Orbiter(int interrupt_millis)
	{
		try
		{
			INTERRUPT_MILLIS = interrupt_millis;
			this.start();
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
			this.tmr_orbiter = new javax.swing.Timer(INTERRUPT_MILLIS, this);
			tmr_orbiter.start();
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
			if(ae.getSource() == this.tmr_orbiter && this.ORBITER_ENABLED)
				process_interrupt();
			
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
			if(!this.ORBITER_ENABLED)
				return false;
			
			if(!this.process_interrupt)
				return false;			
			
			this.process_interrupt = false;
			
			execute_enumeration_action();
									
			this.process_interrupt = true;
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "process_interrupt", e);
		}
		
		this.process_interrupt = true;
		return false;
	}
	
	
	public boolean execute_enumeration_action()
	{
		try
		{
			try{	this.list_files.clear();}	catch(Exception e){this.list_files = new LinkedList<File>();}
			driver.directive("Enumerating...");
			//list files
			if(fleC.exists() && fleC.isDirectory())
				driver.getFileListing(fleC, true, this.arrFileExtension, list_files);
			
			driver.sop("Size: " + list_files.size());
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "execute_enumeration_action", e);
		}
		
		return false;
	}
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
}
