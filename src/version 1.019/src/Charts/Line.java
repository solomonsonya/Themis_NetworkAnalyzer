//credits:http://docs.oracle.com/javafx/2/charts/line-chart.htm

package Charts;

import java.awt.BorderLayout;
import java.awt.event.*;
import java.util.LinkedList;
import java.util.Set;
import java.awt.BorderLayout;
import java.awt.event.*;
import java.util.LinkedList;
import java.awt.event.*;
import Interface.*;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JSplitPane;
import javax.swing.SwingUtilities;
import javax.swing.Timer;
import Driver.*;
import Interface.JTextArea_Solomon;
import javafx.application.Application;
import javafx.application.Platform;
import javafx.embed.swing.JFXPanel;
import javafx.scene.Group;
import javafx.scene.Scene;
import javafx.scene.chart.BarChart;
import javafx.scene.chart.CategoryAxis;
import javafx.scene.chart.LineChart;
import javafx.scene.chart.NumberAxis;
import javafx.scene.chart.XYChart;
import javafx.scene.paint.Color;
import javafx.scene.text.Font;
import javafx.scene.text.Text;
import javafx.stage.Stage;

import javax.swing.*;
import javax.swing.border.BevelBorder;

import Driver.*;

public class Line extends JPanel implements ActionListener
{
	public static final String myClassName = "Line";
	public static Driver driver = new Driver();
	
	public volatile boolean handleInterrupt = true;	
	public volatile Timer tmrInterrupt_UpdateData = null;
	public final int timer_interval_update_data = 200;//1X per second
	public final int max_data_points = 10;
	public volatile int curr_ndex = 0;
	
	public volatile int index_list_series = 0;
	
	
	public volatile String name = "";
	public volatile int val = 0;
	public volatile int beacon_interval = 0;
	public volatile String time = "";

	public JPanel jpnlMain = new JPanel(new BorderLayout());
	
	JButton jbtnSetThreshold = new JButton("Set Chart Threshold");	
	JPanel jpnlNotificationPane = new JPanel(new BorderLayout());
	JLabel jlblData = new JLabel("                    Data:                    ", JLabel.CENTER);
	JTextArea_Solomon jta = new JTextArea_Solomon("", false, "", true);		
	
	
	
	public final JFXPanel jfxPanel = new JFXPanel();
	
	JFrame frame = null;
	
	XYChart.Series series = new XYChart.Series();
	final CategoryAxis xAxis = new CategoryAxis();
	public volatile double lowerBound = -75d;
	public volatile double upperBound = -0d;
	public volatile int tick = Math.abs((int)((lowerBound+0.0)/3.75));
	
	public volatile int high = -80, low = 80, iteration = 0;
	
	//volatile NumberAxis yAxis = new NumberAxis("RSSI", lowerBound, upperBound, 20);
	volatile NumberAxis yAxis = new NumberAxis("COUNT", lowerBound, upperBound, tick);
	
	//Initialize the series to be used
	public volatile XYChart.Series series_one = new XYChart.Series();
	public volatile XYChart.Series series_two = new XYChart.Series();
	public volatile XYChart.Series series_three = new XYChart.Series();
	public volatile XYChart.Series series_four = new XYChart.Series();
	public volatile XYChart.Series series_five = new XYChart.Series();
	public volatile XYChart.Series series_six = new XYChart.Series();
	public volatile XYChart.Series series_seven = new XYChart.Series();
	public volatile XYChart.Series series_eight = new XYChart.Series();
	public volatile XYChart.Series series_nine = new XYChart.Series();
	public volatile XYChart.Series series_ten = new XYChart.Series();
	
	LinkedList<XYChart.Series>list_series = new LinkedList<XYChart.Series>();
	
	JSplitPane_Solomon jspltpne_chart_notification = null;
	public volatile int threshold = 10;
	
	public volatile boolean displayPacketCount  = false;

	public LineChart lineChart = null;
	
	JPanel jpnlNorth = new JPanel(new BorderLayout());
	public volatile JCheckBox jcbEnableChart = new JCheckBox("Enable Graph", true);
	
	
	public String myTitle = "Line Ready";
	public String label_x_axis = "Time";
	public String label_y_axis = "Count";
			
	public Line(String title, String x_axis_label, String y_axis_label)
	{
		try
		{
			myTitle = title;
			label_x_axis = x_axis_label;
			label_y_axis = y_axis_label;
			
			//parent = par;
					
			SwingUtilities.invokeLater(new Runnable() {
				@Override
				public void run() {
					initAndShowGUI();				
				}
			});
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "Constructor - 1", e);
		}
		

		
	}

	private void initAndShowGUI() 
	{
		try
		{
			Platform.runLater(new Runnable() {
				@Override
				public void run() {
					initFX(jfxPanel);
				}
			});
			
			
			
			this.setLayout(new BorderLayout());
			
			this.jpnlNorth.add(BorderLayout.WEST, this.jcbEnableChart);
			this.add(BorderLayout.NORTH, jpnlNorth);
			
			this.add(BorderLayout.CENTER, jpnlMain);
			jpnlMain.setBackground(java.awt.Color.BLACK);
			jpnlMain.setBorder(new BevelBorder(BevelBorder.LOWERED, null, null, null, null));
	//this.jpnlMain.add(BorderLayout.CENTER, jfxPanel);
			
			
			this.jpnlNotificationPane.add(BorderLayout.NORTH, jlblData);
			this.jpnlNotificationPane.add(BorderLayout.CENTER, jta);
			this.jpnlNotificationPane.add(BorderLayout.SOUTH, this.jbtnSetThreshold);			
			this.jspltpne_chart_notification = new JSplitPane_Solomon(JSplitPane.HORIZONTAL_SPLIT, this.jfxPanel, this.jpnlNotificationPane, 0);
			this.jpnlMain.add(BorderLayout.CENTER, jspltpne_chart_notification);
			jlblData.setBorder(new BevelBorder(BevelBorder.LOWERED, null, null, null, null));
			
			jbtnSetThreshold.addActionListener(this);	
			
			jta.jcbAutoScroll.setSelected(false);
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "initAndShowGUI", e);
		}
		
		// This method is invoked on the EDT thread
		

		
		
	}
	
	
	public void actionPerformed(ActionEvent ae)
	{
		try
		{
			if(ae.getSource() == jbtnSetThreshold)
			{
				threshold = driver.getInt("Please specify new threshold:                                                             ", "Current Threshold is to display " + threshold + " element(s)");
			}			
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "ae", e);
		}
	}

	private void initFX(JFXPanel fxPanel) 
	{
		try
		{
			// This method is invoked on the JavaFX thread
			Scene scene = createScene();
			fxPanel.setScene(scene);
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "initFX", e);
		}
		
		
		
		
	}

	private Scene createScene() 
	{
		Scene scene = null;
		
		try
		{
			xAxis.setLabel(label_x_axis);
			yAxis.setLabel(label_y_axis);

			lineChart = new LineChart<String,Number>(xAxis,yAxis);

			lineChart.setTitle(myTitle);

			//Initialize the series to be used
			series_one.setName("1");
			series_two.setName("2");
			series_three.setName("3");
			series_four.setName("4");
			series_five.setName("5");
			series_six.setName("6");
			series_seven.setName("7");
			series_eight.setName("8");
			series_nine.setName("9");
			series_ten.setName("10");
			
					
			list_series.add(series_one);
			list_series.add(series_two);
			list_series.add(series_three);
			list_series.add(series_four);
			list_series.add(series_five);
			list_series.add(series_six);
			list_series.add(series_seven);
			list_series.add(series_eight);
			list_series.add(series_nine);
			list_series.add(series_ten);
			
			
			scene  = new Scene(lineChart);
			
			lineChart.getData().add(series_one);
			lineChart.getData().add(series_two);
			lineChart.getData().add(series_three);
			lineChart.getData().add(series_four);
			lineChart.getData().add(series_five);
			lineChart.getData().add(series_six);
			lineChart.getData().add(series_seven);
			lineChart.getData().add(series_eight);
			lineChart.getData().add(series_nine);		
			lineChart.getData().add(series_ten);
			
			for(int i = 0; i < this.list_series.size(); i++)
			{
				try
				{
					series_one.getData().add(new XYChart.Data(""+i, 0));
					series_two.getData().add(new XYChart.Data(""+i, 0));
					series_three.getData().add(new XYChart.Data(""+i, 0));
					series_four.getData().add(new XYChart.Data(""+i, 0));
					series_five.getData().add(new XYChart.Data(""+i, 0));
					series_six.getData().add(new XYChart.Data(""+i, 0));
					series_seven.getData().add(new XYChart.Data(""+i, 0));
					series_eight.getData().add(new XYChart.Data(""+i, 0));
					series_nine.getData().add(new XYChart.Data(""+i, 0));
					series_ten.getData().add(new XYChart.Data(""+i, 0));
				}
				catch(Exception e)
				{
					continue;
				}
			}

			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "createScene", e);
		}
		
		return (scene);
	}

	
	public boolean display_data(String []arrNames, int arrVals[])
	{
		try
		{
			time = driver.time.getTime_With_Seconds_ONLY();
			
			curr_ndex = (++curr_ndex) % max_data_points;
			
			if(curr_ndex==0)
			{
				high = 0;
				
			}
			
			for(int v : arrVals)
			{
				if(v > high)
				{
					high = v;
					yAxis.setUpperBound(high + 6);
					yAxis.setTickUnit(2 + (int)(high/20));
				}
			}
			
			//
			//Allow the update
			//
			clear_jta("Update Time: " + time + "\n=====================\n");
			
			for(int i = 0; i < threshold && i < arrVals.length; i++)
			{
				
				try
				{	
					name = arrNames[i];
					val = arrVals[i];
					
					//reset counts
					if(val > high)
					{
						high = val;
						yAxis.setUpperBound(high + 6);
						yAxis.setTickUnit(2 + (int)(high/20));
					}
					
					if(val < low)
					{
						low = val;
						yAxis.setLowerBound(0);
						yAxis.setTickUnit(2 + (int)(high/20));
					}
					
					//Set the names to the first 10 for now...
					display_data(list_series.get(i), name, val, time);
				
					//add text to text area
					notify_jta("[" + val + "] " + name);
					
					
				}
				catch(Exception e)
				{
					continue;
				}
				
			}
			
			if(++index_list_series % this.list_series.size() == 0)
				index_list_series = 0;
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "display_data on arrNames and arrVals", e);
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
	
	
	
	public boolean display_data(final XYChart.Series series, final String name, final int count, final String time)
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
		        	series.setName(name);

		        	((XYChart.Data)(series.getData().get(curr_ndex))).setYValue(count);
		        	((XYChart.Data)(series.getData().get(curr_ndex))).setXValue(time);
		        			        						
		        }
		   });
			
			
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop("diaplay_data", myClassName, e);
		}
		
		return false;
	}
	
	/*public boolean updateGraph_RSSI(String line)
	{
		try
		{
			//reject update if not enabled
			if(!this.jcbEnableChart.isSelected())
				return true;
			
			//RSSI```c0:bd:d1:fe:1c:36@@@-71@@@1@@@###cc:29:f5:b0:21:fb@@@-71@@@1@@@CC29F5@@@ CC:29:F5@@@ Apple, Inc.@@@ 1 Infinite Loop@@@ Cupertino  CA@@@ 95014@@@ 95014@@@ Cupertino  CA  95014@@@ US ###4a:d6:2c:de:35:7f@@@-37@@@1@@@###58:48:22:7c:29:6e@@@-67@@@9870@@@584822@@@ 58:48:22@@@ Sony Mobile Communications AB@@@ Nya Vattentornet@@@ Lund  SE@@@ 22128@@@ 22128@@@ Lund  SE  22128@@@ SE ###6e:3b:64:dd:36:30@@@-65@@@1@@@###88:32:9b:7f:47:46@@@-73@@@1@@@88329B@@@ 88:32:9B@@@ Samsung Electro Mechanics co.,LTD.@@@ 93Moo5T. Bangsamak@@@ Bangpakong  Chachoengsao@@@ 24180@@@ 24180@@@ Bangpakong  Chachoengsao  24180@@@ US ###a0:99:9b:9d:01:15@@@-69@@@2@@@A0999B@@@ A0:99:9B@@@ Apple, Inc.@@@ 1 Infinite Loop@@@ Cupertino  CA@@@ 95014@@@ 95014@@@ Cupertino  CA  95014@@@ US ###08:70:45:00:38:ae@@@-65@@@19470@@@087045@@@ 08:70:45@@@ Apple, Inc.@@@ 1 Infinite Loop@@@ CUPERTINO  CA@@@ 95014@@@ 95014@@@ CUPERTINO  CA  95014@@@ US ###d8:a2:5e:b6:3b:fb@@@-73@@@26826@@@D8A25E@@@ D8:A2:5E@@@ Apple, Inc.@@@ 1 Infinite Loop@@@ CUPERTINO  CA@@@ 95014@@@ 95014@@@ CUPERTINO  CA  95014@@@ US ###d0:87:e2:39:8c:87@@@-71@@@1@@@###dc:86:d8:05:ba:34@@@-69@@@2@@@###00:11:21:a1:98:b1@@@-71@@@1@@@001121@@@ 00:11:21@@@ Cisco Systems, Inc@@@ 80 West Tasman Drive@@@ San Jose  CA@@@ 94568@@@ 94568@@@ San Jose  CA  94568@@@ US ###90:03:b7:f8:bb:e8@@@-63@@@9@@@9003B7@@@ 90:03:B7@@@ PARROT@@@ 174 quai de jemmapes@@@ PARIS@@@ 7510@@@ 7510@@@ PARIS    7510@@@ FR ###cc:25:ef:7d:ef:92@@@-71@@@15@@@CC25EF@@@ CC:25:EF@@@ Apple, Inc.@@@ 1 Infinite Loop@@@ Cupertino  CA@@@ 95014@@@ 95014@@@ Cupertino  CA  95014@@@ US ###90:fd:61:09:3b:0f@@@-67@@@7@@@90FD61@@@ 90:FD:61@@@ Apple, Inc.@@@ 1 Infinite Loop@@@ Cupertino  CA@@@ 95014@@@ 95014@@@ Cupertino  CA  95014@@@ US ###08:70:45:6e:67:5d@@@-67@@@1@@@087045@@@ 08:70:45@@@ Apple, Inc.@@@ 1 Infinite Loop@@@ CUPERTINO  CA@@@ 95014@@@ 95014@@@ CUPERTINO  CA  95014@@@ US ###bc:6e:64:ea:f3:ad@@@-71@@@1@@@BC6E64@@@ BC:6E:64@@@ Sony Mobile Communications AB@@@ Nya Vattentornet@@@ Lund  SE@@@ 22128@@@ 22128@@@ Lund  SE  22128@@@ SE ###38:f2:3e:89:c1:30@@@-67@@@29458@@@38F23E@@@ 38:F2:3E@@@ Microsoft Mobile Oy@@@ Keilalahdentie 4@@@ Espoo@@@ 2150@@@ 02150@@@ Espoo    02150@@@ FI ###c2:6e:87:cf:d5:8a@@@-69@@@1@@@###f2:c3:97:85:ca:fa@@@-57@@@3414@@@###60:fe:c5:83:28:f4@@@-65@@@9104@@@60FEC5@@@ 60:FE:C5@@@ Apple, Inc.@@@ 1 Infinite Loop@@@ Cupertino  CA@@@ 95014@@@ 95014@@@ Cupertino  CA  95014@@@ US ###40:30:04:25:d4:6a@@@-65@@@22429@@@403004@@@ 40:30:04@@@ Apple, Inc.@@@ 1 Infinite Loop@@@ CUPERTINO  CA@@@ 95014@@@ 95014@@@ CUPERTINO  CA  95014@@@ US ###2a:69:25:57:2a:9d@@@-65@@@1@@@###ac:29:3a:af:b7:f8@@@-69@@@9@@@AC293A@@@ AC:29:3A@@@ Apple, Inc.@@@ 1 Infinite Loop@@@ Cupertino  CA@@@ 95014@@@ 95014@@@ Cupertino  CA  95014@@@ US ###1e:c0:fc:b1:fa:4b@@@-71@@@1@@@###48:74:6e:a6:e1:aa@@@-57@@@204@@@48746E@@@ 48:74:6E@@@ Apple, Inc.@@@ 1 Infinite Loop@@@ Cupertino  CA@@@ 95014@@@ 95014@@@ Cupertino  CA  95014@@@ US ###ac:ee:9e:21:b7:e9@@@-59@@@14274@@@ACEE9E@@@ AC:EE:9E@@@ Samsung Electronics Co.,Ltd@@@ #94-1, Imsoo-Dong@@@ Gumi  Gyeongbuk  730-350@@@ -1@@@ -1@@@ Gumi  Gyeongbuk  730-350@@@ KR ###3a:d0:30:19:02:17@@@-69@@@11@@@###
			String [] arr_first = line.split(Chart_Controller.delimiter_begin_category);
			String [] arr_data = arr_first[1].split(Chart_Controller.delimiter_category);
			
			//now each device is at each element of arr_data
			String [] arr_device = null;
			
			name = "";
			val = 0;
			beacon_interval = 0;
			
			
			/////// cut line
			list_mac = driver.driver_interface.getList_ACTIVE_MAC();
			
			if(list_mac == null || list_mac.size() < 1)
				return false;
			
			
			time = driver.time.getTime_With_Seconds_ONLY();
			curr_ndex = (++curr_ndex) % threshold;
			
			//
			//Allow the update
			//
			clear_jta("Update Time: " + time + "\n=====================\n");
			
			
			//reset high and low here
			
			
			for(int i = 0; i < threshold && i < list_mac.size(); i++)
			{
				
				try
				{										
					node = list_mac.get(i);
					
					if(node.VENDOR == null || node.VENDOR.trim().equals("") || node.VENDOR.trim().equalsIgnoreCase("unknown"))
						name = node.MAC;
					else
						name = node.MAC + node.VENDOR;
					
					val = Integer.parseInt(node.RSSI.trim());	
										
					//Set the names to the first 10 for now...
					display_data(list_series.get(i), name, val, time);
					
					//add text to text area
					notify_jta("[" + val + "] " + name);
					
				}
				catch(Exception e)
				{
					continue;
				}
				
				//reset counts
				if(iteration++ % this.max_data_points == 0)
				{
					iteration = 0;
					high = val +5;
					low = val - 5;
					
					yAxis.setUpperBound(high + 5);
					yAxis.setLowerBound(low - 5);
					//yAxis.setTickUnit(5);
					
				}
				
				if(val > high)
				{
					high = val;
					yAxis.setUpperBound(high + 2);
					//yAxis.setTickUnit(5);
				}
				if(val < low)
				{
					low = val;
					yAxis.setLowerBound(low - 2);
					//yAxis.setTickUnit(5);
				}
			}
			
			//set the new high and low bounds
			
			list_mac.clear();
			list_mac = null;
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "updateGraph_RSSI", e);
		}
		
		return false;
	}*/


}
