/**
 * @author Solomon Sonya
 */

//credits:http://docs.oracle.com/javafx/2/charts/line-chart.htm

package Charts;

import java.awt.BorderLayout;
import java.awt.GridLayout;
import java.awt.event.*;
import java.util.LinkedList;
import Interface.*;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JSplitPane;
import javax.swing.SwingUtilities;
import javax.swing.Timer;

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

public class Bar extends JPanel implements ActionListener
{
	public static final String myClassName = "Bar";
	public static Driver driver = new Driver();
	
	public volatile String x_label = "", y_label = "";
		
	public volatile Scene scene = null;
	public final JFXPanel fxPanel = new JFXPanel();
			
	XYChart.Series series = new XYChart.Series();
	public volatile String first_name = "";
	public volatile String []arr_split_name = null;
	final CategoryAxis xAxis = new CategoryAxis();
	final NumberAxis yAxis = new NumberAxis();
	
	public volatile boolean threshold_updated = false;
	
	//Initialize the series to be used
	XYChart.Series [] arrSeries = new XYChart.Series[9];
	
	/*XYChart.Series series_Apple = new XYChart.Series();
	XYChart.Series series_Samsung = new XYChart.Series();
	XYChart.Series series_HTC = new XYChart.Series();
	XYChart.Series series_Nokia = new XYChart.Series();
	XYChart.Series series_Microsoft = new XYChart.Series();
	XYChart.Series series_Motorola = new XYChart.Series();
	XYChart.Series series_Intel = new XYChart.Series();
	XYChart.Series series_Cisco = new XYChart.Series();
	XYChart.Series series_Murata = new XYChart.Series();*/
	
	public volatile boolean need_to_update_title = false;
	
	int count_apple = 0;
	int count_samsung = 0;
	int count_htc = 0;
	int count_nokia = 0;
	int count_microsoft = 0;
	int count_motorola = 0;
	int count_intel = 0;
	int count_cisco = 0;
	int count_murata = 0;
	
	public volatile String name = "";
	public volatile int val = 0;
	public volatile int beacon_interval = 0;
	public volatile String time = "";
	
	
	public JPanel jpnlJCB_Options = new JPanel(new BorderLayout());
	public JPanel jpnlOptions = new JPanel(new BorderLayout());
	
	/**Update this from the seperate container interface class*/
	public volatile JButton jbtnUpdateChart = new JButton("Update Chart");
	
	JButton jbtnSetThreshold = new JButton("Set Chart Threshold");	
	public volatile int index = 0;
	JPanel jpnlNotificationPane = new JPanel(new BorderLayout());
	JLabel jlblData = new JLabel("                    Data:                    ", JLabel.CENTER);
	JTextArea_Solomon jta = new JTextArea_Solomon("", false, "", true);		
	JSplitPane_Solomon jspltpne_chart_notification = null;
	public volatile double threshold = 10;
	
	public BarChart barChart = null;
	
	public String myTitle = "";
	
	public JPanel jpnlMain = new JPanel(new BorderLayout());
	
	JPanel jpnlNorth = new JPanel(new BorderLayout());
	public volatile JCheckBox jcbEnableChart = new JCheckBox("Enable Graph", true);
	
	
	
	public Bar(String title, String xlabel, String ylabel)
	{
		try
		{
			myTitle = title;
			x_label = xlabel;
			y_label = ylabel;
			
			
			SwingUtilities.invokeLater(new Runnable() {
				@Override
				public void run() {
					initAndShowGUI();				
				}
			});
			
//			for(int i = 0; i < max_data_points; i++)
//			{
//				//populate with dummy vars
//				attack_time.add("Time [" + i + "] ");
//				attack_delta.add(DEPRECATED_Parser_Agent_TCPDUMP.attacks_detected_this_interval);
//				
//			}
		}
		
		catch(Exception e)
		{
			driver.directive("Initialization Bar Configuration");
		}
		
	}

	private void initAndShowGUI() 
	{	
		try
		{
			Platform.runLater(new Runnable() {
				@Override
				public void run() {
					initFX(fxPanel);
				}
			});
			
			this.jpnlNorth.add(BorderLayout.WEST, this.jcbEnableChart);
			
			this.setLayout(new BorderLayout());
			this.add(BorderLayout.NORTH, jpnlNorth);
			this.add(BorderLayout.CENTER, jpnlMain);
			jpnlMain.setBackground(java.awt.Color.BLACK);
			jpnlMain.setBorder(new BevelBorder(BevelBorder.LOWERED, null, null, null, null));		
			this.jpnlMain.add(BorderLayout.CENTER, fxPanel);
			//display_data();
			
			this.jpnlNotificationPane.add(BorderLayout.NORTH, jlblData);
			this.jpnlNotificationPane.add(BorderLayout.CENTER, jta);
			
			
			jpnlJCB_Options.add(BorderLayout.EAST, jta.jcbAutoScroll);
			jpnlJCB_Options.add(BorderLayout.WEST, jta.jcbRejectUpdate);
			jpnlJCB_Options.add(BorderLayout.SOUTH, jbtnUpdateChart);
			jpnlOptions.add(BorderLayout.NORTH, jpnlJCB_Options);
			jpnlOptions.add(BorderLayout.CENTER, jbtnSetThreshold);
			jpnlOptions.add(BorderLayout.SOUTH, this.jta.jbtnExportData);
			
			this.jpnlNotificationPane.add(BorderLayout.SOUTH, this.jpnlOptions);			
			jlblData.setBorder(new BevelBorder(BevelBorder.LOWERED, null, null, null, null));
			this.jspltpne_chart_notification = new JSplitPane_Solomon(JSplitPane.HORIZONTAL_SPLIT, this.fxPanel, this.jpnlNotificationPane, 0);
			jbtnSetThreshold.addActionListener(this);		
			jta.jcbAutoScroll.setSelected(false);
			this.jpnlMain.add(BorderLayout.CENTER, jspltpne_chart_notification);
					
			jta.validate();
		}

		catch(Exception e)
		{
			driver.directive("Configuration Bar II");
		}
	}
	
	

	private void initFX(JFXPanel fxPanel) 
	{
		try
		{
			// This method is invoked on the JavaFX thread
			scene = createScene();
			fxPanel.setScene(scene);
		}
		catch(Exception e)
		{
			driver.directive("Configuration Bar III");
		}
		
	}
	
		
	private Scene createScene() 
	{
		try
		{
			xAxis.setLabel(x_label);
			yAxis.setLabel(y_label);
			

			barChart = new BarChart<String,Number>(xAxis,yAxis);

			barChart.setTitle(myTitle);
			
			//init series
			for(int i = 0; i < this.arrSeries.length; i++)
			{
				arrSeries[i] = new XYChart.Series();
			}
			
			//set names
			arrSeries[0].setName("1");
			arrSeries[1].setName("2");
			arrSeries[2].setName("3");
			arrSeries[3].setName("4");
			arrSeries[4].setName("5");
			arrSeries[5].setName("6");
			arrSeries[6].setName("7");
			arrSeries[7].setName("8");
			arrSeries[8].setName("9");
			

			//Initialize the series to be used
			/*this.series_Apple.setName("Apple");
			this.series_Cisco.setName("Cisco");
			this.series_HTC.setName("HTC");
			this.series_Intel.setName("Intel");
			this.series_Microsoft.setName("Microsoft");
			this.series_Motorola.setName("Motorola");
			this.series_Murata.setName("Murata");
			this.series_Nokia.setName("Nokia");
			this.series_Samsung.setName("Samsung");*/
			
			Scene scene  = new Scene(barChart);
			/*barChart.getData().add(series_Apple);
			barChart.getData().add(series_Samsung);
			barChart.getData().add(series_Cisco);
			barChart.getData().add(series_Intel);
			barChart.getData().add(series_Microsoft);
			barChart.getData().add(series_Motorola);
			barChart.getData().add(series_Nokia);
			barChart.getData().add(series_Murata);
			barChart.getData().add(series_HTC);	*/
			
			//add initial data
			for(int i = 0; i < this.arrSeries.length; i++)
			{
				barChart.getData().add(arrSeries[i]);
				arrSeries[i].getData().add(new XYChart.Data("0", 0));
			}
			
			/*series_Apple.getData().add(new XYChart.Data("0", 0));
			series_Samsung.getData().add(new XYChart.Data("0", 0));
			series_Cisco.getData().add(new XYChart.Data("0", 0));
			series_Intel.getData().add(new XYChart.Data("0", 0));
			series_Microsoft.getData().add(new XYChart.Data("0", 0));
			series_Motorola.getData().add(new XYChart.Data("0", 0));
			series_Nokia.getData().add(new XYChart.Data("0", 0));
			series_Murata.getData().add(new XYChart.Data("0", 0));
			series_HTC.getData().add(new XYChart.Data("0", 0));*/
			
			

			return (scene);
		}
		catch(Exception e)
		{
			driver.directive("Bar Configuration IV");
		}
		
		return (scene);
	}

	

	public void actionPerformed(ActionEvent ae)
	{
		try
		{
			if(ae.getSource() == jbtnSetThreshold)
			{
				threshold = driver.getDouble("Please specify new threshold: ", "Current Threshold is to display" + threshold + " element(s)");

				this.threshold_updated = true;
			}			

		}
		catch(Exception e)
		{
			driver.eop(myClassName, "ae", e);
		}
	}
	
	public boolean display_data(final String [] arrNames, final int [] arrValues)
	{
		try
		{
			//reject update if not enabled
			if(!this.jcbEnableChart.isSelected())
				return true;
			
			if(arrNames == null || arrValues == null)
        		return false;
			
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
		        			barChart.setTitle(myTitle);
		        			need_to_update_title = false;
		        		}
		        		catch(Exception e)
		        		{
		        			
		        		}
		        		
		        	}
		        	
		        	time = driver.time.getTime_With_Seconds_ONLY();
		        	
		        	clear_jta("Update Time: " + time + "\n=====================\n");
		        	
		        	//ensure we have the proper number of series
		        	if(arrNames.length != arrSeries.length || threshold_updated)
		        		updateSeries(arrNames, arrValues);
		        	
		        	//increment the values
		        	for(int i = 0; i < arrSeries.length && i < threshold; i++)
		        	{
		        		try
		        		{
		        			//reset the data
				        	((XYChart.Data)(arrSeries[i].getData().get(0))).setYValue(arrValues[i]);			        			        			
		        			notify_jta("[" + arrValues[i] + "] " + arrNames[i]);
		        			
		        		}
		        		catch(Exception e)
		        		{
		        			continue;
		        		}
		        	}
			
		        }
		   });
			
			
			//System.gc();
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop("diaplay_data", myClassName, e);
		}
		
		return false;
	}
	
	public boolean updateSeries(String [] arrNames, int [] arrValues)
	{
		try
		{
			//reject update if not enabled
			if(!this.jcbEnableChart.isSelected())
				return true;
			
			if(arrNames == null || arrNames.length < 1 || arrValues == null || arrValues.length < 1)
				return false;
			
			//create the new series
			arrSeries = new XYChart.Series[arrNames.length];

			//initialize the new series
			for(int i = 0; i < this.arrSeries.length; i++)
			{
				//init
				arrSeries[i] = new XYChart.Series();

				//assign name here!
				arrSeries[i].setName(arrNames[i]);
				
				/*try
				{
					arr_split_name = arrNames[i].trim().split(" ");
					first_name = this.arr_split_name[0].trim();
				}
				catch(Exception e)
				{
					first_name = "";
				}
				
				//assign value
				arrSeries[i].getData().add(new XYChart.Data(first_name, arrValues[i]));*/
				
				arrSeries[i].getData().add(new XYChart.Data("", arrValues[i]));
			}

			//remove old series from data graph
			barChart.getData().clear();
			
			/*try
			{
				index = 0;
				while(barChart.getData().size() > 0)
					barChart.getData().remove(index++);
			}
			catch(Exception e)
			{
				
			}*/
								

			//update data
			for(int i = 0; i < this.arrSeries.length && i < threshold; i++)
			{
				//add the new series
				barChart.getData().add(arrSeries[i]);				
			}
			
			this.threshold_updated = false;
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "updateSeries", e);
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
