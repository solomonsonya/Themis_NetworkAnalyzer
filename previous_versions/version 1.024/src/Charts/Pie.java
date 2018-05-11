/**
 * @author Solomon Sonya
 */

package Charts;

import javafx.application.Application;
import javafx.application.Platform;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.embed.swing.JFXPanel;
import javafx.geometry.Side;
import javafx.scene.Group;
import javafx.scene.Scene;
import javafx.scene.chart.CategoryAxis;
import javafx.scene.chart.LineChart;
import javafx.scene.chart.NumberAxis;
import javafx.scene.chart.PieChart;
import javafx.scene.chart.XYChart;
import javafx.scene.paint.Color;
import javafx.scene.text.Font;
import javafx.scene.text.Text;
import javafx.stage.Stage;
import Driver.*;
import Interface.JTextArea_Solomon;

import java.awt.event.*;
import java.awt.*;

import Driver.*;
import Driver.*;

import java.awt.event.*;

import javax.swing.*;
import javax.swing.border.BevelBorder;

import java.awt.*;

import javax.swing.*;
import javax.swing.border.BevelBorder;

import java.awt.event.*;
import java.awt.*;
import java.util.Collections;
import java.util.LinkedList;


public class Pie extends JPanel implements ActionListener
{
	public static Driver driver = new Driver();
	public static final String myClassName = "Pie";
	
	public volatile Bar myCorrespondingBarChart = null;
	
	
	public JPanel jpnlMain = new JPanel(new BorderLayout());
	

	public final JFXPanel jfxPanel = new JFXPanel();	
	Scene scene = null;	
	ObservableList<PieChart.Data> pieChart_data = null;
	
	int other = 0;
	//public double threshold = .025; //eg do not show values if they are less than 2 % expressed in the entire sample
	
	public double threshold = 10; //eg do not show values if they are less than 2 % expressed in the entire sample
	
	public PieChart pieChart = null;
	
	public volatile int size = 0, search_count = 0, max_loop_count = 0, index = 0, index_list_count = 0;
	public volatile LinkedList<Integer> list_value_counts = new LinkedList<Integer>();
	public volatile String [] array_main = null;
	public volatile String []array = null;
	public volatile String []arrTemp = null;
	public volatile String []arrName = new String []{"ready"};
	public volatile int []arrValue = new int[]{1};
	public volatile long total = 0;

	public volatile String name = "";
	public volatile int val = 0;
	public volatile int beacon_interval = 0;
	public volatile String time = "";

			
	JSplitPane jspltpne_chart_notification = null;
	
	public volatile boolean need_to_update_title = false;
	
	
	public String myTitle = "";
	
	public volatile String [][] arrPieVals = null;
	
	public JPanel jpnlJCB_Options = new JPanel(new BorderLayout());
	public JPanel jpnlOptions = new JPanel(new BorderLayout());
	
	/**Update this from the seperate container interface class*/
	public volatile JButton jbtnUpdateChart = new JButton("Update Chart");
	
	JButton jbtnSetThreshold = new JButton("Set Chart Threshold");	
	JPanel jpnlNotificationPane = new JPanel(new BorderLayout());
	JLabel jlblData = new JLabel("                    Data:                    ", JLabel.CENTER);
	JTextArea_Solomon jta = new JTextArea_Solomon("", false, "", true);		
	
	JPanel jpnlNorth = new JPanel(new BorderLayout());
	public volatile JCheckBox jcbEnableChart = new JCheckBox("Enable Graph", true);
	
	
	public Pie(String title, Bar corresponding_bar_chart_if_applicable)
	{
		try
		{
			myTitle = title;
			this.setLayout(new BorderLayout());
			
			this.jpnlNorth.add(BorderLayout.WEST, this.jcbEnableChart);
			this.add(BorderLayout.NORTH, jpnlNorth);
			
			this.add(BorderLayout.CENTER, jpnlMain);
			jpnlMain.setBackground(java.awt.Color.BLACK);
			jpnlMain.setBorder(new BevelBorder(BevelBorder.LOWERED, null, null, null, null));
			myCorrespondingBarChart = corresponding_bar_chart_if_applicable;
			
			SwingUtilities.invokeLater(new Runnable() 
			{
				@Override
				public void run() 
				{
					init();				
				}
			});
			
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "Constructor - 1", e);
		}
	}
	
	private void init() 
	{
		try
		{
			Platform.runLater(new Runnable() 
			{
				@Override
				public void run() 
				{
					initJFX_Panel(jfxPanel);
				}
			});
		}
		catch(Exception e)
		{
			driver.directive("Pie Configuration I");
		}
		
	}
	
	private void initJFX_Panel(JFXPanel JFX_Panel) 
	{
		try
		{
			//driver.sop("Setup II");
			
			pieChart_data = FXCollections.observableArrayList(
					new PieChart.Data("Data Set 1", 1),
		            new PieChart.Data("Data Set 2", 1),
		            new PieChart.Data("Data Set 3TC", 1));
					
				pieChart = new PieChart(pieChart_data);
				pieChart.setTitle(myTitle);
				pieChart.setLegendSide(Side.LEFT);
				
			scene  = new Scene(pieChart);
			JFX_Panel.setScene(scene);
			
	//this.jpnlMain.add(BorderLayout.CENTER, jfxPanel);
			
			jpnlJCB_Options.add(BorderLayout.EAST, jta.jcbAutoScroll);
			jpnlJCB_Options.add(BorderLayout.WEST, jta.jcbRejectUpdate);
			jpnlJCB_Options.add(BorderLayout.SOUTH, jbtnUpdateChart);
			jpnlOptions.add(BorderLayout.NORTH, jpnlJCB_Options);
			jpnlOptions.add(BorderLayout.CENTER, jbtnSetThreshold);
			jpnlOptions.add(BorderLayout.SOUTH, this.jta.jbtnExportData);
			
			this.jpnlNotificationPane.add(BorderLayout.NORTH, jlblData);
			this.jpnlNotificationPane.add(BorderLayout.CENTER, jta);
			this.jpnlNotificationPane.add(BorderLayout.SOUTH, this.jpnlOptions);		
			
			this.jspltpne_chart_notification = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, this.jfxPanel, this.jpnlNotificationPane);
			jspltpne_chart_notification.setOneTouchExpandable(true);
			jspltpne_chart_notification.setDividerLocation(1000);
			this.jspltpne_chart_notification.setDividerSize(10);
			
			this.jpnlMain.add(BorderLayout.CENTER, jspltpne_chart_notification);
			
			jbtnSetThreshold.addActionListener(this);
			
			
			jlblData.setBorder(new BevelBorder(BevelBorder.LOWERED, null, null, null, null));
			jta.jcbAutoScroll.setSelected(false);
			
			display_data(true);
		}
		catch(Exception e)
		{
			driver.directive("Pie Configuration II");
		}
		
		
	}
	
	public void actionPerformed(ActionEvent ae)
	{
		try
		{
			if(ae.getSource() == jbtnSetThreshold)
			{
				double newThreshold = driver.getDouble("Please specify new threshold: ", "Current Threshold is " + threshold);
				threshold = newThreshold;
			}			
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "ae", e);
		}
	}
	
	public boolean updatePIE_from_full_line(String line)
	{
		try
		{
			//reject update if not enabled
			if(!this.jcbEnableChart.isSelected())
				return true;
			
			//PIE```PARROT@@@10###INTEL CORPORATE@@@43###LG INNOTEK@@@2###HON HAI PRECISION IND. CO.,LTD.@@@12###EXTREME NETWORKS@@@5###ARUBA NETWORKS@@@6###Z-COM, INC.@@@13###SONY MOBILE COMMUNICATIONS AB@@@76###SAMSUNG ELECTRO-MECHANICS@@@5###LENOVO MOBILE COMMUNICATION TECHNOLOGY LTD.@@@2###LG ELECTRONICS (MOBILE COMMUNICATIONS)@@@6###SEIKO EPSON CORPORATION@@@2###TEXAS INSTRUMENTS@@@2###PRIVATE@@@2###CISCO SYSTEMS, INC@@@122###MICROSOFT MOBILE OY@@@17###GUANGDONG OPPO MOBILE TELECOMMUNICATIONS CORP.,LTD@@@2###SAMSUNG ELECTRO MECHANICS CO.,LTD.@@@22###SAMSUNG ELECTRO MECHANICS CO., LTD.@@@113###AISIN AW CO.,LTD.@@@2###MOTOROLA MOBILITY LLC, A LENOVO COMPANY@@@32###NOKIA CORPORATION@@@17###ONEPLUS TECH (SHENZHEN) LTD@@@3###NUDIAN ELECTRON CO., LTD.@@@2###MICROSOFT CORPORATION@@@32###XIAOMI COMMUNICATIONS CO LTD@@@6###BYD PRECISION MANUFACTURE COMPANY LTD.@@@3###SAMSUNG ELECTRO MECHANICS@@@4###SUGA ELECTRONICS LIMITED@@@13###SHENZHEN TINNO MOBILE TECHNOLOGY CORP.@@@2###GIONEE COMMUNICATION EQUIPMENT CO,LTD.SHENZHEN@@@2###SUMMIT DATA COMMUNICATIONS@@@2###FORD MOTOR COMPANY@@@3###HTC CORPORATION@@@30###WISTRON NEWEB CORP.@@@2###ASUSTEK COMPUTER INC.@@@4###AZUREWAVE TECHNOLOGY INC.@@@9###MICROSOFT@@@2###COMPAL COMMUNICATIONS, INC.@@@2###HUAWEI TECHNOLOGIES CO.,LTD@@@57###APPLE, INC.@@@685###LG ELECTRONICS@@@15###LITEON TECHNOLOGY CORPORATION@@@17###SONOS, INC.@@@2###AMPAK TECHNOLOGY, INC.@@@2###ZEBRA TECHNOLOGIES INC@@@4###SAMSUNG ELECTRONICS CO.,LTD@@@129###SAMSUNG ELECTRO-MECHANICS CO., LTD.@@@3###ZTE CORPORATION@@@2###UNIVERSAL GLOBAL SCIENTIFIC INDUSTRIAL CO., LTD.@@@5###WISOL@@@12###ALPS ELECTRIC CO.,LTD.@@@2###MURATA MANUFACTURING CO., LTD.@@@43###
			
//array_main = line.split(Chart_Controller.delimiter_begin_category);
			//driver.sop("1: " + array_main[1]);
			
			//PARROT@@@10###INTEL CORPORATE@@@43###LG INNOTEK@@@2###HON HAI PRECISION IND. CO.,LTD.@@@12###EXTREME NETWORKS@@@5###ARUBA NETWORKS@@@6###Z-COM, INC.@@@13###SONY MOBILE COMMUNICATIONS AB@@@76###SAMSUNG ELECTRO-MECHANICS@@@5###LENOVO MOBILE COMMUNICATION TECHNOLOGY LTD.@@@2###LG ELECTRONICS (MOBILE COMMUNICATIONS)@@@6###SEIKO EPSON CORPORATION@@@2###TEXAS INSTRUMENTS@@@2###PRIVATE@@@2###CISCO SYSTEMS, INC@@@122###MICROSOFT MOBILE OY@@@17###GUANGDONG OPPO MOBILE TELECOMMUNICATIONS CORP.,LTD@@@2###SAMSUNG ELECTRO MECHANICS CO.,LTD.@@@22###SAMSUNG ELECTRO MECHANICS CO., LTD.@@@113###AISIN AW CO.,LTD.@@@2###MOTOROLA MOBILITY LLC, A LENOVO COMPANY@@@32###NOKIA CORPORATION@@@17###ONEPLUS TECH (SHENZHEN) LTD@@@3###NUDIAN ELECTRON CO., LTD.@@@2###MICROSOFT CORPORATION@@@32###XIAOMI COMMUNICATIONS CO LTD@@@6###BYD PRECISION MANUFACTURE COMPANY LTD.@@@3###SAMSUNG ELECTRO MECHANICS@@@4###SUGA ELECTRONICS LIMITED@@@13###SHENZHEN TINNO MOBILE TECHNOLOGY CORP.@@@2###GIONEE COMMUNICATION EQUIPMENT CO,LTD.SHENZHEN@@@2###SUMMIT DATA COMMUNICATIONS@@@2###FORD MOTOR COMPANY@@@3###HTC CORPORATION@@@30###WISTRON NEWEB CORP.@@@2###ASUSTEK COMPUTER INC.@@@4###AZUREWAVE TECHNOLOGY INC.@@@9###MICROSOFT@@@2###COMPAL COMMUNICATIONS, INC.@@@2###HUAWEI TECHNOLOGIES CO.,LTD@@@57###APPLE, INC.@@@685###LG ELECTRONICS@@@15###LITEON TECHNOLOGY CORPORATION@@@17###SONOS, INC.@@@2###AMPAK TECHNOLOGY, INC.@@@2###ZEBRA TECHNOLOGIES INC@@@4###SAMSUNG ELECTRONICS CO.,LTD@@@129###SAMSUNG ELECTRO-MECHANICS CO., LTD.@@@3###ZTE CORPORATION@@@2###UNIVERSAL GLOBAL SCIENTIFIC INDUSTRIAL CO., LTD.@@@5###WISOL@@@12###ALPS ELECTRIC CO.,LTD.@@@2###MURATA MANUFACTURING CO., LTD.@@@43###

//array = array_main[1].split(Chart_Controller.delimiter_category);
			
			if(array_main == null)
				return false;
			if(array == null)
				return false;
			
			//<NAME>@@@VALUE
			//<NAME>@@@VALUE
			//...
			//<NAME>@@@VALUE
			arrName = new String[array.length];
			arrValue= new int[array.length];
			
			time = driver.time.getTime_With_Seconds_ONLY();
			clear_jta("Update Time: " + time + "\n=====================\n");
			
			//
			//at this point, we have the number of unique devices and the counts, check if the bars displayed
			//reflect this number, if so, then just add as normal. otherwise, remove everything from the bar
			//and redraw to now reflect the new number of items reported from the collector
			//
			
			
			total = 0;

			//calculate total
			for(int i = 0; i < array.length; i++)
			{
				try
				{					
					//split the name from the value
//arrTemp = array[i].split(Chart_Controller.delimiter_value);
					//driver.sop("3: " + arrTemp[0]);
					
					arrName[i] = arrTemp[0].trim();
					arrValue[i] = Integer.parseInt(arrTemp[1].trim());					
					
					total += arrValue[i];
					
					this.notify_jta("[" + arrValue[i] + "]" + arrName[i]);
				}
				catch(Exception e)
				{
					e.printStackTrace(System.out);
					continue;
				}
			}
			
			if(total < 1)
				return false;
			
			//otherwise, populate values
			
			arrPieVals = new String[arrName.length][2];
			
			display_data(true);
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "updatePIE", e);
		}
		
		return false;
	}
	
	public boolean display_data(String [] names, int [] values, boolean update_corresponding_bar_chart_if_applicable)
	{
		try
		{
			
			this.arrName = names;
			this.arrValue = values;
			return display_data(update_corresponding_bar_chart_if_applicable);			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "display_data", e);
		}
		
		return false;
	}
	
	public boolean display_data(final boolean update_corresponding_bar_chart_if_applicable)
	{
		try
		{
			//reject update if not enabled
			if(!this.jcbEnableChart.isSelected())
				return true;
			
			//populate with new contents			
			Platform.runLater(new Runnable() 
			{
		        @Override
		        public void run() 
		        {		        			        			        	
		        	if(need_to_update_title)
		        	{
		        		try
		        		{
		        			pieChart.setTitle(myTitle);
		        			need_to_update_title = false;
		        		}
		        		catch(Exception e)
		        		{
		        			
		        		}
		        		
		        	}
		        	
		        	pieChart_data.clear();
		        	other = 0;
		        		     
		        	if(arrName != null)
		        	{

			        	time = driver.time.getTime_With_Seconds_ONLY();		        	
			        	clear_jta("Update Time: " + time + "\n=====================\n");
			        	
			        	
			        		for(int i = 0; i < arrName.length && i < threshold; i++)
			        		{		        		
				        		try
				        		{
				        			pieChart_data.add(new PieChart.Data(arrName[i], arrValue[i]));
				        			

									notify_jta("[" + arrValue[i] + "] " + arrName[i]);
				        					        			
				        		}
				        		catch(Exception e)
				        		{
				        			continue;
				        		}
			        		}
		        	}
		        	
		        		
		        				        		
		        		if(update_corresponding_bar_chart_if_applicable && myCorrespondingBarChart != null)
		        		{
		        			//Chart_Controller.bar_unique_device_vendor_count.display_data(arrName, arrValue);
		        			myCorrespondingBarChart.display_data(arrName, arrValue);
		        		}
		        }
		   });
			
			this.validate();
		
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "diaplay_data", e);
		}
		
		return false;
	}
	
	/**
	 * null is ok
	 * @param initial_msg
	 * @return
	 */
	public boolean clear_jta(String initial_msg)
	{
		try
		{
			if(!this.jta.jcbRejectUpdate.isSelected())
			{
				if(initial_msg == null)
					this.jta.jta.setText("");
				else
					this.jta.jta.setText(initial_msg);
			}
			
			return true;
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "clear_jta", e);
		}
		
		return false;
	}
	
	public boolean notify_jta(String line)
	{
		try
		{
			if(!this.jta.jcbRejectUpdate.isSelected())
			{
				this.jta.append(line);
			}
			
			return true;
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "notify_jta", e);
		}
		
		return false;
	}
	
	
}
