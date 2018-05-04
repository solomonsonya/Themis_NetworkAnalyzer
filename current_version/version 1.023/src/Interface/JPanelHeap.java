package Interface;

import javax.swing.*;
import javax.swing.Timer;
import javax.swing.border.BevelBorder;
import Process.*;
import Cookie.Cookie_Container_Host_System;
import Driver.*;
//import Sound.ThreadSound;
import GEO_Location.*;
import java.awt.event.*;
import java.awt.*;
import java.text.*;
import java.util.*;
import Parser.*;

public class JPanelHeap extends JPanel implements Runnable, ActionListener
{
	public static final String myClassName = "JPanelHeap";
	public static Driver driver = new Driver();
	
	JLabel jlblAvailableHeap = new JLabel("Initializing. Standby... ");
	JLabel jlblConsumedHeap = new JLabel("... ");
	JLabel jlblMaxHeap = new JLabel("... ");
	JLabel jlblTotalHeap = new JLabel("... ");
	public JLabel jlblUpTime = new JLabel("...");
	
	public static volatile String last_sensor_update = "Awaiting input...";
	JLabel jlblSocketUpdate = new JLabel("");
	
	public static JLabel jlblEncryptionKey = new JLabel("Encryption Key: //NOT SET//");
	
	long available_heap = 0;
	long max_heap = 0;
	long consumed_heap = 0;
	long total_heap = 0;
	
	public static final long start_time = System.currentTimeMillis();
	
	DecimalFormat deci_formatter = new DecimalFormat("0.00");
	
	JPanel jpnlStats = new JPanel(new GridLayout(1,5));
	JPanel jpnlOptions = new JPanel();
	
	
	public static volatile JCheckBox jcbGEO_ResolutionEnabled = new JCheckBox("GEO", false);
	public static volatile JCheckBox jcbCookie_Orbiter_Enabled = new JCheckBox("Cookies", false);
	public static volatile JCheckBox jcbNetstat_Orbiter_Enabled = new JCheckBox("Netstat", false);
	public static volatile JCheckBox jcbProcess_Orbiter_Enabled = new JCheckBox("Process", false); 
	public static volatile JCheckBox jcbSoundEnabled = new JCheckBox("Sound", true);
	public static volatile JCheckBox jcbLoggingEnabled = new JCheckBox("Logging", true);
	public static volatile JCheckBox jcbParserEnabled = new JCheckBox("Parser", true);
	public Timer tmr = null;
	
	public JPanelHeap()
	{
		try
		{
			//this.setLayout(new GridLayout(1,8,4,4));
			this.setLayout(new BorderLayout());
			
			jpnlStats.add(this.jlblUpTime);
			jpnlStats.add(this.jlblAvailableHeap)		;
			jpnlStats.add(this.jlblConsumedHeap)			;
			jpnlStats.add(this.jlblTotalHeap)			;
			jpnlStats.add(this.jlblMaxHeap)				;
			
			jpnlOptions.add(this.jlblEncryptionKey)		;
			jpnlOptions.add(this.jcbParserEnabled)		;
			jpnlOptions.add(this.jcbSoundEnabled)		;
			jpnlOptions.add(this.jcbLoggingEnabled)		;			
			jpnlOptions.add(this.jcbGEO_ResolutionEnabled)		;
			jpnlOptions.add(this.jcbNetstat_Orbiter_Enabled)		;
			jpnlOptions.add(this.jcbCookie_Orbiter_Enabled)		;
			jpnlOptions.add(this.jcbProcess_Orbiter_Enabled)		;
			
			jpnlOptions.add(this.jlblSocketUpdate)		;
			
			this.add(BorderLayout.CENTER, jpnlStats);
			this.add(BorderLayout.EAST, jpnlOptions);
			
			jcbLoggingEnabled.setSelected(Log.logging_enabled);
			
			
			
			this.tmr = new Timer(1000, this);
			tmr.start();
			
			jcbSoundEnabled.addActionListener(this);
			jcbParserEnabled.addActionListener(this);
			jcbLoggingEnabled.addActionListener(this);
			jcbGEO_ResolutionEnabled.addActionListener(this);
			jcbNetstat_Orbiter_Enabled.addActionListener(this);
			jcbProcess_Orbiter_Enabled.addActionListener(this);
			jcbCookie_Orbiter_Enabled.addActionListener(this);
			jcbSoundEnabled.setToolTipText("Specifies if Sound is Enabled");
			jcbParserEnabled.setToolTipText("Disable to dismiss packets received for processing");
			jcbLoggingEnabled.setToolTipText("Specifies if Logging is Enabled");
			jcbGEO_ResolutionEnabled.setToolTipText("Specifies if GEO Resolution is Enabled. NOTE: This may create additional resource consumption.");
			jlblSocketUpdate.setToolTipText("Specifies the Last Time an update input has been received in the system");
			jcbNetstat_Orbiter_Enabled.setToolTipText("<html>Specifies if Netstat Orbiter should be enabled to constantly attribute <br>network connections on host machine to the process responsible for each connection </html>");
			jcbProcess_Orbiter_Enabled.setToolTipText("<html>Specifies if Process Orbiter should be enabled to constantly check host system for running <br>process information as well as attribute parent and offspring processes to network activity (if Netstat Orbiter is enabled)</html>");
			jcbCookie_Orbiter_Enabled.setToolTipText("Specifies if Cookie Orbiter should be enabled to routinely check system for new cookies found on disk");
			
			this.validate();
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "Constructor - 1");
		}
	}
		
	
	public void actionPerformed(ActionEvent ae)
	{
		try
		{
			if(ae.getSource() == this.tmr)
			{
				update_times();
			}
			else if(ae.getSource() == jcbSoundEnabled)
			{
				//try	{	ThreadSound.SOUND_ENABLED = jcbSoundEnabled.isSelected();	}	catch(Exception e){}
				
				if(jcbSoundEnabled.isSelected())
					driver.directive("SOUND ENABLED");
				else
					driver.directive("SOUND DISABLED");
			}
			
			else if(ae.getSource() == jcbParserEnabled)
			{
				Parser.PARSER_ENABLED = jcbParserEnabled.isSelected();
				
				if(Parser.PARSER_ENABLED)
					driver.directive("Parser Enabled");
				else
					driver.directive("Parser Disabled");
			}
			
			else if(ae.getSource() == this.jcbLoggingEnabled)
			{
				Log.logging_enabled = jcbLoggingEnabled.isSelected();
				
				if(Log.logging_enabled)
					driver.directive("LOGGING ENABLED");
				else
					driver.directive("LOGGING DISABLED");
			}
			
			else if(ae.getSource() == this.jcbGEO_ResolutionEnabled)
			{
				GEO_Location.AUTOMATIC_GEO_RESOLUTION_ENABLED = this.jcbGEO_ResolutionEnabled.isSelected();

				if(GEO_Location.AUTOMATIC_GEO_RESOLUTION_ENABLED)
					driver.directive("GEO Resolution ENABLED");
				else
					driver.directive("GEO Resolution DISABLED");
			}
			
			else if(ae.getSource() == jcbCookie_Orbiter_Enabled)
			{
				Cookie_Container_Host_System.auto_update_cookies = jcbCookie_Orbiter_Enabled.isSelected();
				
				if(Cookie_Container_Host_System.auto_update_cookies)
					driver.directive("Cookie Orbiter ENABLED");
				else
					driver.directive("Cookie Orbiter DISABLED");
			}
			
			else if(ae.getSource() == jcbNetstat_Orbiter_Enabled)
			{
				Node_Netstat.NETSTAT_ORBITER_ENABLED = jcbNetstat_Orbiter_Enabled.isSelected();
				
				if(Node_Netstat.NETSTAT_ORBITER_ENABLED)
					driver.directive("Netstat Orbiter Enabled.");
				else
					driver.directive("Netstat Orbiter Disabled.");				
			}
			
			else if(ae.getSource() == jcbProcess_Orbiter_Enabled)
			{
				Node_Process.PROCESS_ORBITER_ENABLED = jcbProcess_Orbiter_Enabled.isSelected();
				
				if(Node_Process.PROCESS_ORBITER_ENABLED)
					driver.directive("Process Orbiter Enabled.");
				else
					driver.directive("Process Orbiter Disabled.");				
			}
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "ae");
		}
		
		this.validate();
	}
	
	public boolean update_times()
	{
		try
		{
			this.available_heap = Runtime.getRuntime().freeMemory();
			this.max_heap = Runtime.getRuntime().maxMemory();
			this.total_heap = Runtime.getRuntime().totalMemory();
			this.consumed_heap = total_heap - available_heap;
			
			jlblMaxHeap.setText("Max Heap: " + convert_size(max_heap));
			jlblTotalHeap.setText("Total Heap: " + convert_size(total_heap));
			jlblAvailableHeap.setText("  Available Heap: " + convert_size(available_heap));
			jlblConsumedHeap.setText("Consumed Heap: " + convert_size(consumed_heap));
			jlblUpTime.setText("  Up Time: " +getTimeInterval_WithDays(System.currentTimeMillis(), start_time));
			jlblSocketUpdate.setText(last_sensor_update);
			//this.validate();
			return true;	
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "update_times");
		}
		
		return false;
	}
	
	public String convert_size(double size)
	{
		try
		{
			if(size / 1e12 >= 1)
				return "" + deci_formatter.format(((size + 0.0) / 1e12)) + " tb  ";
			if(size / 1e9 >= 1)
				return ("" + deci_formatter.format(((size + 0.0) / 1e9))) + " GBs  ";
			if(size / 1e6 >= 1)
				return ("" + deci_formatter.format(((size + 0.0) / 1e6))) + " MBs  ";
			if(size / 1e3 >= 1)
				return ("" + deci_formatter.format(((size + 0.0) / 1e3))) + " KBs  ";
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "convert_size");
		}
		
		return size + " bytes"; 
	}


	@Override
	public void run() {
		// TODO Auto-generated method stub
		
	}
	
	
	public  String getTimeInterval_WithDays(long currTime_millis, long prevTime_millis)
	{
		String timeInterval = "UNKNOWN";
		try
		{
			SimpleDateFormat dateFormat = new SimpleDateFormat("DD:HH:mm:ss");
			dateFormat.setTimeZone(TimeZone.getTimeZone("GMT"));
			
			//long currTime_millis = System.currentTimeMillis();//get the current time in milliseconds
			
			long interval = currTime_millis - prevTime_millis;
			
			timeInterval = dateFormat.format(new Date(interval));		
			
		}
		catch(Exception e)
		{
			System.out.println("Error caught in calculateTimeInterval_From_Present_Time mtd");
		}
		
		return timeInterval;
	}
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	

}
