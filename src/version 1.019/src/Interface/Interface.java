package Interface;

import java.io.*;
import java.awt.*;
import java.awt.event.*;
import java.net.*;
import java.security.*;
import java.util.*;
import Sensor.*;
import nmap.NMap;
import nmap.Node_NMap;
import Map.*;
import javax.imageio.ImageIO;
import javax.swing.*;
import javax.swing.border.BevelBorder;
import javax.swing.border.TitledBorder;
import Driver.*;
import OUI_Parser.Node_OUI;
import OUI_Parser.Node_OUI_Container_GUI;
import Parser.Application;
import Parser.ThdParserSocket;
import Profile.*;
import Profile.Resolution;
import Profile.SOURCE;
//import Sound.ThreadSound;
import Charts.*;


public class Interface extends Thread implements Runnable, ActionListener
{
	public static final String myClassName = "Interface";
	public static volatile Driver driver = new Driver();

	public static volatile Map_D3 map_d3 = new Map_D3();
	
	public static volatile JFrame jfrm = null;
	public static volatile JMenuBar menu_bar = null;
	public static volatile JMenu jmnuFile = null;
		public static volatile JMenuItem jmnuitm_Close = null;
		public static volatile JMenu jmnuEncryption = null;
			public static volatile ButtonGroup bgEncryption = null;
			public static volatile JRadioButtonMenuItem jrbEncryptionEnabled = null;
			public static volatile JRadioButtonMenuItem jrbEncryptionDisabled = null;
			public static volatile JMenuItem jmnuitm_Import = null;
			
		public static volatile JMenu jmnuNetworkMap = null;
			public static volatile ButtonGroup bgNetworkMap = null;
			public static volatile JRadioButtonMenuItem jrbNetworkMapEnabled = null;
			public static volatile JRadioButtonMenuItem jrbNetworkMapDisabled = null;
			
			public static volatile JPanel jpnlNotification_South = new JPanel(new GridLayout(1,1,2,2));
			public static volatile JButton jbtnMonitorInSummary = new JButton("Monitor in Network Summary");
			public static volatile JMenuItem jmnuitem_MonitorInSummary = new JMenuItem("Monitor in Network Summary");
			
			
	public volatile static LinkedList<Tuple> list_snapshot_packet_count_tuples = new LinkedList<Tuple>();
	public JPanel jpnlMain = null;
	public volatile static  JPanelNetworkInterface_Solomon jpnlNetworkInterfaceCards = null;
	
	public JPanel jpnlNORTH = null;
	public JPanel jpnlCENTER = null;
	public JPanel jpnlSOUTH = null;
	
	public JPanelHeap jpnlHeap = null;
	public JPanelTime jpnlTime = null;
	
	public static volatile boolean i_am_updating_summary = false;
	public static volatile String [] snapshot_packet_names = null;
	public static volatile int [] snapshot_packet_vals = null;
	public static volatile int index_snapshot = 0;
	
	
	
	public volatile String selected_value = "";
	
	public JSplitPane_Solomon jsplitpane_MAIN = null;
	public JSplitPane_Solomon jsplitpane_NetworkSummary = null;
		public JTabbedPane jtabbedPane_NetworkSummary_TOP  = null;
		public JTabbedPane jtabbedPane_BOTTOM_LEFT  = null;
		public JTabbedPane jtabbedPane_BOTTOM_RIGHT  = null;
		public JSplitPane_Solomon jsplitpane_SOURCE_NODES_OUI = null;
		public JSplitPane_Solomon jsplitpane_NetworkStatistics = null;
		
		
		public JSplitPane_Solomon jsplitpane_BOTTOM = null;
	
	public JTabbedPane jtabbedPane_MAIN  = null;
	public JTabbedPane jtabbedPane_CONSOLE  = null;
	
	public volatile JTextArea_Solomon jpnlConsole = null;
	public volatile JTextArea_Solomon jpnlSignature = null;
	public volatile JTextArea_Solomon jpnlNetworkMap = null;
	
	public volatile JButton jbtnImportNetworkMapFile = null;
	
	public volatile JLabel jlblNoDataToLoadYet = new JLabel("No Data to Load Yet...", JLabel.CENTER);
	public volatile JPanel jpnl_jtblSourceNodes = new JPanel(new BorderLayout());
	/**Note, this is initialized this way because we do not know the form and structure of the packets being analyzed. Thus Themis must first learn the traffic, and then display accordingly*/
	public volatile JTable_Solomon jtblSourceNodes = null;
	
	public volatile JPanel jpnl_jtblALERT = new JPanel(new BorderLayout());
	public volatile JTable_Solomon jtbl_ALERTS = null;
	
	public volatile JPanel jpnl_jtblResolution = new JPanel(new BorderLayout());
	public volatile JTable_Solomon jtblResolution = null;
	
	public volatile JPanel jpnl_jtblApplicationCategorization_out = new JPanel(new BorderLayout());
	public volatile JTable_Solomon jtblApplicationCategorization_out = null;
	
	public volatile JTable_Solomon jtblCookies_NetworkCapture = null;
	public volatile JTable_Solomon jtblCookies_HostSystem = null;
	public volatile JTable_Solomon jtblOUI_In_Use = null;
	public volatile JTable_Solomon jtblNetworkProcesses = null;
	
	public volatile JTable_Solomon jtblNetworkMap = null;
	
	public static volatile Resolution resolution_data_view = null;
	public static volatile Resolution application_data_view = null;
	public static volatile String displayString_resolution = "";
	public static volatile String displayString_application = "";
	
	public static volatile Application application_search = null;
	public static volatile String application_display_string = "";
	
	public volatile static JLabel jlblNodesCount = new JLabel("Nodes: 0", JLabel.CENTER);
	public volatile static JLabel jlblResourcesCount = new JLabel("Resources: 0", JLabel.CENTER);
	public volatile static JLabel jlblNOT_CONNECTED = new JLabel("NOT CONNECTED", JLabel.CENTER);
	
	public static volatile Bar bar_network_statistics = new Bar("Network Statistics", "Protocol", "Count");
	public static volatile Pie pie_network_statistics = new Pie("Network Statistics", bar_network_statistics);
	
	public static volatile Bar bar_NODE_statistics = new Bar("Node Statistics", "Protocol", "Count");
	public static volatile Pie pie_NODE_statistics = new Pie("Node Statistics", bar_NODE_statistics);

	public static volatile Bar bar_RESOURCE_statistics_EXTERNAL = new Bar("Resource Statistics [EXTERNAL]", "Protocol", "Count");
	public static volatile Pie pie_RESOURCE_statistics_EXTERNAL = new Pie("Resource Statistics [EXTERNAL]", bar_RESOURCE_statistics_EXTERNAL);
	
	public static volatile Bar bar_RESOURCE_statistics_INTERNAL = new Bar("Resource Statistics [INTERNAL]", "Protocol", "Count");
	public static volatile Pie pie_RESOURCE_statistics_INTERNAL = new Pie("Resource Statistics [INTERNAL]", bar_RESOURCE_statistics_INTERNAL);
	
	public static volatile Bar bar_devices_on_network = new Bar("Communicating Devices", "Device Type", "Count");
	public static volatile Pie pie_devices_on_network = new Pie("Communicating Devices", bar_devices_on_network);
	
	public static volatile Line line_packet_snapshot = new Line("Packet Summary Snapshot", "Time", "COUNT");
	
	/**
	 * Duplicate entries can exist because we intentionally store duplicate resource values for a tree name as well as a tree's IP address .
	 * All of these values link the same resource node, however, may have multiple keys that are used to point to the same resource bcs a single domain name may have multiple ip addresses
	 * all linking to the same source. therefore, we use this to include only unique nodes first
	 */
	public static volatile TreeMap<String, Resolution> included_node = new TreeMap<String, Resolution>(); 
	
	public Interface()
	{
		try
		{
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
			initialize_component();
			
			execute_functions();
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "run", e);
		}
	}
	
	public boolean execute_functions()
	{
		try
		{
			StandardInListener.update_cookies_host_system(false);
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "execute_functions", e);
		}
		
		return false;
	}
	
	public boolean initialize_component()
	{
		try
		{
			driver.setLookAndFeel();
			try 		 {				 UIManager.setLookAndFeel("com.sun.java.swing.plaf.windows.WindowsLookAndFeel");				 SwingUtilities.updateComponentTreeUI(jfrm);				 /*updateComponentTreeUI(this);	*/	    }	catch (Exception e) 	    {	    }
			
			jfrm = new JFrame();			
			jfrm.setTitle(Driver.FULL_NAME);
			jfrm.setSize(new Dimension(1100,800));
			jfrm.setVisible(true);
			jfrm.setLayout(new BorderLayout());
			
			try
			{
				jfrm.setLocationRelativeTo(null);
			}
			catch(Exception e)
			{
				Dimension dim = Toolkit.getDefaultToolkit().getScreenSize();
				jfrm.setLocation(dim.width/2-jfrm.getSize().width/2, dim.height/2-jfrm.getSize().height/2);
			}
			
			//
			//menu
			//
			menu_bar = new JMenuBar();
			
			//file
			this.jmnuFile = new JMenu("File");
			jmnuFile.setMnemonic(KeyEvent.VK_F);
			menu_bar.add(jmnuFile);
			
			jmnuitm_Import = new JMenuItem("Import");
			jmnuitm_Close = new JMenuItem("Close");
			jmnuEncryption = new JMenu("Encryption");
				jrbEncryptionEnabled = new JRadioButtonMenuItem("Encryption Enabled");
				jrbEncryptionDisabled = new JRadioButtonMenuItem("Encryption Disabled", true);
				bgEncryption = new ButtonGroup();
				bgEncryption.add(this.jrbEncryptionEnabled);
				bgEncryption.add(this.jrbEncryptionDisabled);
				jmnuEncryption.add(this.jrbEncryptionEnabled);
				jmnuEncryption.add(this.jrbEncryptionDisabled);
				
			jmnuNetworkMap = new JMenu("Network Map");
				jrbNetworkMapEnabled = new JRadioButtonMenuItem("Network Map Enabled");
				jrbNetworkMapDisabled = new JRadioButtonMenuItem("Network Map Disabled", true);
				bgNetworkMap = new ButtonGroup();
				bgNetworkMap.add(this.jrbNetworkMapEnabled);
				bgNetworkMap.add(this.jrbNetworkMapDisabled);
				jmnuNetworkMap.add(this.jrbNetworkMapEnabled);
				jmnuNetworkMap.add(this.jrbNetworkMapDisabled);
				
				if(NMap.NMAP_ENABLED)
					jrbNetworkMapEnabled.setSelected(true);
			
			jmnuFile.add(jmnuEncryption);
			jmnuFile.add(jmnuNetworkMap);
			jmnuFile.add(jmnuitm_Import);
			jmnuFile.add(jmnuitm_Close);
			
			this.jrbEncryptionDisabled.addActionListener(this);
			this.jrbEncryptionEnabled.addActionListener(this);
			this.jmnuitm_Close.addActionListener(this);
			this.jmnuitm_Import.addActionListener(this);
			this.jrbNetworkMapEnabled.addActionListener(this);
			this.jrbNetworkMapDisabled.addActionListener(this);
			
			this.jfrm.setJMenuBar(menu_bar);
			
			jpnlMain = new JPanel(new BorderLayout());
				jfrm.add(BorderLayout.CENTER, jpnlMain);
			
			jpnlNORTH = new JPanel(new BorderLayout());
			jpnlCENTER = new JPanel(new BorderLayout());
			jpnlSOUTH = new JPanel(new BorderLayout());
			
			jpnlMain.add(BorderLayout.NORTH, jpnlNORTH);
			jpnlMain.add(BorderLayout.CENTER, jpnlCENTER);
			jpnlMain.add(BorderLayout.SOUTH, jpnlSOUTH);
			
			
			//
			//SPECIAL PANELS
			//
			jpnlNetworkInterfaceCards = new JPanelNetworkInterface_Solomon();
			jpnlNORTH.add(BorderLayout.SOUTH, jpnlNetworkInterfaceCards);
			
			
			jpnlTime = new JPanelTime();
				jpnlNORTH.add(BorderLayout.CENTER, jpnlTime);
				jpnlNORTH.setBorder(BorderFactory.createBevelBorder(BevelBorder.LOWERED));
				jpnlTime.jpnlTimes.add(jlblNodesCount);
				jpnlTime.jpnlTimes.add(jlblResourcesCount);
				jpnlTime.jpnlTimes.add(this.jlblNOT_CONNECTED);
				
				jlblNodesCount.setFont(new Font("Helvetica", Font.BOLD, 14));
				jlblResourcesCount.setFont(new Font("Helvetica", Font.BOLD, 14));
				jlblNOT_CONNECTED.setFont(new Font("Helvetica", Font.BOLD, 14));
				jlblNOT_CONNECTED.setOpaque(true);
				
				if(ThdParserSocket.ALL_CONNECTIONS.size() > 0)
				{
					StandardInListener.intrface.jlblNOT_CONNECTED.setText("CONNECTED");
					StandardInListener.intrface.jlblNOT_CONNECTED.setForeground(Color.white);
					StandardInListener.intrface.jlblNOT_CONNECTED.setBackground(Color.green.darker().darker());					
					
				}
				else if(Sensor.list_sensors != null && Sensor.list_sensors.size() > 0)
				{
					StandardInListener.intrface.jlblNOT_CONNECTED.setText("SENSOR");
					StandardInListener.intrface.jlblNOT_CONNECTED.setForeground(Color.white);
					StandardInListener.intrface.jlblNOT_CONNECTED.setBackground(Color.blue.darker());	
				}
				else
				{
					StandardInListener.intrface.jlblNOT_CONNECTED.setText("NOT CONNECTED");
					jlblNOT_CONNECTED.setBackground(Color.red);
					jlblNOT_CONNECTED.setForeground(Color.yellow);
				}
				
				
				
			jpnlHeap = new JPanelHeap();				
				jpnlSOUTH.add(BorderLayout.CENTER, jpnlHeap);
				jpnlSOUTH.setBorder(BorderFactory.createBevelBorder(BevelBorder.LOWERED));
												
			
				
			//
			//JTABBED PANE
			//
			jtabbedPane_MAIN = new JTabbedPane(JTabbedPane.TOP);
			jtabbedPane_CONSOLE = new JTabbedPane(JTabbedPane.TOP);
			jsplitpane_MAIN = new JSplitPane_Solomon(JSplitPane.VERTICAL_SPLIT, jtabbedPane_MAIN, jtabbedPane_CONSOLE, 300);
				jpnlCENTER.add(BorderLayout.CENTER, jsplitpane_MAIN);
			
			

			
			jlblNoDataToLoadYet.setFont(new Font("Courier", Font.BOLD, 30));
			//jpnl_jtblProtocol.add(BorderLayout.CENTER, jlblNoDataToLoadYet);
				
			//
			jpnlConsole = new JTextArea_Solomon("Standard Out Console", true, "Command Transmission", true);			
			jtabbedPane_CONSOLE.addTab("Console", jpnlConsole);
			
			jpnlSignature = new JTextArea_Solomon("Signatures", true, "Signature Update", false);
			jtabbedPane_CONSOLE.addTab("Signatures", jpnlSignature);
			
			jpnlNetworkMap = new JTextArea_Solomon("Network Map", true, "Network Map", true);			
			jtabbedPane_CONSOLE.addTab("Network Map", jpnlNetworkMap);
			//jpnlNetworkMap.jpnlcheckBox.setLayout(new FlowLayout());
			
			jpnlNetworkMap.jbtnSend.removeActionListener(jpnlNetworkMap);
			jpnlNetworkMap.jtf.removeActionListener(jpnlNetworkMap);
			jpnlNetworkMap.jtf.addActionListener(this);
			jpnlNetworkMap.jbtnSend.addActionListener(this);
			jpnlNetworkMap.jbtnSend.setEnabled(false);
			jpnlNetworkMap.jtf.setEditable(false);
			jbtnImportNetworkMapFile = new JButton("Import");
			this.jbtnImportNetworkMapFile.setToolTipText("Import Network Map File");
			jbtnImportNetworkMapFile.addActionListener(this);			
			jpnlNetworkMap.jpnlcheckBox.add(jbtnImportNetworkMapFile);
			
			String [] alerts_header = new String[]{"SOURCE", "TIME", "Detection System", "Signature", "Details"};
			this.jtbl_ALERTS = new JTable_Solomon(false, alerts_header, alerts_header, "Alerts", null, null, true, -1, "", false, 3);
			jpnl_jtblALERT.add(BorderLayout.CENTER, jtbl_ALERTS);
			
			String [] init = new String[]{"SOURCE", "MAC", "ALERT", "FIRST_CONTACT", "LAST_CONTACT", "PROTOCOL"};			
			this.jtblSourceNodes = new JTable_Solomon(false, init, init, "Source Nodes", null, null, true, -1, "", false, 4);
			jpnl_jtblSourceNodes.add(BorderLayout.CENTER, jtblSourceNodes);
			
			try
			{							
				//jpnlNotification_South.add(jbtnMonitorInSummary);
				jpnl_jtblSourceNodes.add(BorderLayout.SOUTH, jpnlNotification_South);
				jtblSourceNodes.jpnlNotification_South.add(jbtnMonitorInSummary);
				jbtnMonitorInSummary.addActionListener(this);
				
				jtblSourceNodes.jpopup_SelectedRow.add(jmnuitem_MonitorInSummary);
				jmnuitem_MonitorInSummary.addActionListener(this);
			}
			catch(Exception e){}
			
			
			String [] destination_node_header = new String[]{"SOURCE", "ALERT", "CARDINALITY", "DOMAIN NAME", "NAME SERVER", "FIRST_CONTACT_TIME", "RESOLUTION_COMPLETE", "INTERNAL_IPv4"};
			this.jtblResolution = new JTable_Solomon(false, destination_node_header, destination_node_header, "Destination Nodes / Requested Domain Resources", null, null, true, -1, "", false, 3);
			jtblResolution.process_double_click_for_resolution = true;
			jpnl_jtblResolution.add(BorderLayout.CENTER, jtblResolution);
			jtblResolution.load_list = true;
			
			
			String [] network_categorization_tab_out = new String[]{"DESTINATION KEY", "APPLICATION", "PROTOCOL", "PORT", "DOMAIN NAME", "CARDINALITY", "ALERT"};
			this.jtblApplicationCategorization_out = new JTable_Solomon(false, network_categorization_tab_out, network_categorization_tab_out, "Application Categorization", null, null, true, -1, "", false, 3);
			jtblApplicationCategorization_out.process_double_click_for_application= true;
			jpnl_jtblApplicationCategorization_out.add(BorderLayout.CENTER, jtblApplicationCategorization_out);
			
			String [] cookies = new String[]{"SOURCE", "MAC", "DEVICE IDENTIFIER (OUI)", "COOKIE", "DOMAIN NAME", "URI"};
			this.jtblCookies_NetworkCapture = new JTable_Solomon(false, cookies, cookies, "Cookies - Network Capture", null, null, false, 120, "", false, 3);
			
			String [] cookies_host = new String[]{"IP ADDRESS", "USER NAME", "HOST SYSTEM", "FILE CREATION", "LAST ACCESSED", "LAST MODIFIED", "COOKIE NAME", "COOKIE VALUE", "WEB SERVER", "FLAGS", "EXPIRATION TIME (LOW)", "EXPIRATION TIME (HIGH)", "CREATION TIME (LOW)", "CREATION TIME (HIGH)", "RECORD #", "FILE NAME", "PATH", "FILE DB TYPE"};
			this.jtblCookies_HostSystem = new JTable_Solomon(false, cookies_host, cookies_host, "Cookies - Host System", null, null, false, 120, "", false, 3);
			jtblCookies_HostSystem.jtfFilter.setVisible(false);
			jtblCookies_HostSystem.jbtnClearAndRefresh.removeActionListener(jtblCookies_HostSystem);
			jtblCookies_HostSystem.jbtnClearAndRefresh.addActionListener(this);
			this.jtblCookies_HostSystem.process_double_click_for_cookies_host_system = true;
			
			
			String [] nmap = new String[]{"ADDRESS", "MAC", "HOST NAME", "OPEN PORTS", "RUNNING", "DEVICE TYPE", "DEVICE", "OS", "CPE", "OS CPE", "OS DETAILS", "NETWORK DISTANCE", "SERVICE INFO", "USER", "WORKGROUP", "SYSTEM TIME", "ACCOUNT USED", "AUTHENTICATION LEVEL", "CHALLENGE RESPONSE", "MESSAGE SIGNING", "START TIME"};
			this.jtblNetworkMap = new JTable_Solomon(false, nmap, nmap, "Network Map", null, null, false, 120, "", false, 3);
			jtblNetworkMap.jtfFilter.setVisible(false);
			jtblNetworkMap.jbtnClearAndRefresh.removeActionListener(jtblNetworkMap);
			jtblNetworkMap.jbtnClearAndRefresh.addActionListener(this);			
			this.jtblNetworkMap.process_double_click_for_network_map = true;
			
			
			
			String [] oui_in_use = new String[]{"COMPANY NAME", "LINKED DEVICE COUNT", "UNIQUE OUI", "OUI"};
			this.jtblOUI_In_Use = new JTable_Solomon(false, oui_in_use, oui_in_use, "Unique Device Listing", null, null, false, 120, "", false, 3);
			jtblOUI_In_Use.jtfFilter.setVisible(false);
			jtblOUI_In_Use.jbtnClearAndRefresh.removeActionListener(jtblOUI_In_Use);
			jtblOUI_In_Use.jbtnClearAndRefresh.addActionListener(this);			
			this.jtblOUI_In_Use.process_double_click_for_update_oui_list = true;
			
			//for /F "tokens=1-5 delims= " %A in ('netstat -ano') do echo %A,%B,%C,%D,%E
			String [] netstat = new String[]{"PID", "PROCESS", "HOST IP", "REMOTE ADDRESS", "SESSION NAME", "MEM USAGE", "TERMINATION TIME", };
			this.jtblOUI_In_Use = new JTable_Solomon(false, oui_in_use, oui_in_use, "Unique Device Listing", null, null, false, 120, "", false, 3);
			jtblOUI_In_Use.jtfFilter.setVisible(false);
			jtblOUI_In_Use.jbtnClearAndRefresh.removeActionListener(jtblOUI_In_Use);
			jtblOUI_In_Use.jbtnClearAndRefresh.addActionListener(this);			
			this.jtblOUI_In_Use.process_double_click_for_update_oui_list = true;
			
			jsplitpane_SOURCE_NODES_OUI = new JSplitPane_Solomon(JSplitPane.HORIZONTAL_SPLIT, jpnl_jtblSourceNodes, jtblOUI_In_Use, 600);
			
			
			jsplitpane_NetworkStatistics = new JSplitPane_Solomon(JSplitPane.HORIZONTAL_SPLIT, pie_network_statistics, pie_devices_on_network, 300);
			
			
			
			
			//
			//NETWORK SUMMARY PANEL
			//			
			jtabbedPane_NetworkSummary_TOP = new JTabbedPane(JTabbedPane.TOP);
			jtabbedPane_BOTTOM_LEFT = new JTabbedPane(JTabbedPane.TOP);
			jtabbedPane_BOTTOM_RIGHT = new JTabbedPane(JTabbedPane.TOP);
			
			
			
			
			
			jtabbedPane_BOTTOM_LEFT.addTab("Network Statistics",  bar_network_statistics);
			jtabbedPane_BOTTOM_LEFT.addTab("Node Statistics",  bar_NODE_statistics);
			bar_network_statistics.jbtnUpdateChart.addActionListener(this);
			bar_NODE_statistics.jbtnUpdateChart.addActionListener(this);
			
			jtabbedPane_NetworkSummary_TOP.addTab("Network Statistics",  jsplitpane_NetworkStatistics);
			jtabbedPane_NetworkSummary_TOP.addTab("Node Statistics",  pie_NODE_statistics);
			pie_network_statistics.jbtnUpdateChart.addActionListener(this);
			pie_NODE_statistics.jbtnUpdateChart.addActionListener(this);
			
			jtabbedPane_NetworkSummary_TOP.addTab   ("Resource Statistics [EXTERNAL]",  pie_RESOURCE_statistics_EXTERNAL);
			jtabbedPane_BOTTOM_LEFT.addTab("Resource Statistics [EXTERNAL]",  bar_RESOURCE_statistics_EXTERNAL);
			pie_RESOURCE_statistics_EXTERNAL.jbtnUpdateChart.addActionListener(this);
			bar_RESOURCE_statistics_EXTERNAL.jbtnUpdateChart.addActionListener(this);
			
			jtabbedPane_NetworkSummary_TOP.addTab   ("Resource Statistics [INTERNAL]",  pie_RESOURCE_statistics_INTERNAL);
			jtabbedPane_BOTTOM_LEFT.addTab("Resource Statistics [INTERNAL]",  bar_RESOURCE_statistics_INTERNAL);
			pie_RESOURCE_statistics_INTERNAL.jbtnUpdateChart.addActionListener(this);
			bar_RESOURCE_statistics_INTERNAL.jbtnUpdateChart.addActionListener(this);
			
			
			//jtabbedPane_NetworkSummary_TOP.addTab   ("Communicating Devices",  pie_devices_on_network);
			jtabbedPane_BOTTOM_LEFT.addTab("Communicating Devices",  bar_devices_on_network);
			pie_devices_on_network.jbtnUpdateChart.addActionListener(this);
			bar_devices_on_network.jbtnUpdateChart.addActionListener(this);
			
			jtabbedPane_BOTTOM_RIGHT.addTab("Network Packet Summary Snapshot",  line_packet_snapshot);
									
			jsplitpane_BOTTOM = new JSplitPane_Solomon(JSplitPane.HORIZONTAL_SPLIT, jtabbedPane_BOTTOM_LEFT, jtabbedPane_BOTTOM_RIGHT, 300);
			
			jsplitpane_NetworkSummary = new JSplitPane_Solomon(JSplitPane.VERTICAL_SPLIT, jtabbedPane_NetworkSummary_TOP, jsplitpane_BOTTOM, 500);
			
			//
			//MAIN PANEL
			//
			//jtabbedPane_MAIN.addTab("Main", new JPanel());
			jtabbedPane_MAIN.addTab("Network Summary", jsplitpane_NetworkSummary);
			//jtabbedPane_MAIN.addTab("Source Nodes",jpnl_jtblSourceNodes);
			jtabbedPane_MAIN.addTab("Source Nodes",this.jsplitpane_SOURCE_NODES_OUI);
			
			jtabbedPane_MAIN.addTab("Destination Nodes / Requested Domain Resources",jtblResolution);
			jtabbedPane_MAIN.addTab("Cookies - Network Capture",jtblCookies_NetworkCapture);
			jtabbedPane_MAIN.addTab("Cookies - Host System",	jtblCookies_HostSystem);
			jtabbedPane_MAIN.addTab("Network Map",jtblNetworkMap);
			jtabbedPane_MAIN.addTab("Application Categorization [OUT]",jtblApplicationCategorization_out);			
			jtabbedPane_MAIN.addTab("Alerts",jpnl_jtblALERT);
			
			
			configure_signature_panel(jpnlSignature);
			configure_jtblResolution();
			configure_jtblApplicationCategorization();
			configure_jtblCookies_NetworkCapture();
			
			
			
			
			
			jfrm.addWindowListener(new java.awt.event.WindowAdapter()
			{
				public void windowClosing(java.awt.event.WindowEvent e)
				{
					close();
				}
			});
			
			jfrm.setDefaultCloseOperation(JFrame.DO_NOTHING_ON_CLOSE);
			
			jfrm.validate();
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "initialize_component", e);
		}
		
		return false;
	}
	
	public static boolean update_packet_summary_snapshot()
	{
		try
		{
			if(i_am_updating_summary)
				return false;
			
			if(SOURCE.tree_snapshot_packet_count == null || SOURCE.tree_snapshot_packet_count.isEmpty())
				return false;
			
			i_am_updating_summary = true;
			
			//create new if needed
			if(snapshot_packet_names == null)
			{
				snapshot_packet_names = new String[SOURCE.tree_snapshot_packet_count.size()];
				snapshot_packet_vals = new int[SOURCE.tree_snapshot_packet_count.size()];
			}
			
			//only do a new allocation if required, otherwise, we'll just re-init below
			else if(snapshot_packet_names.length != SOURCE.tree_snapshot_packet_count.size())
			{
				snapshot_packet_names = new String[SOURCE.tree_snapshot_packet_count.size()];
				snapshot_packet_vals = new int[SOURCE.tree_snapshot_packet_count.size()];
			}
			
			
			//get the list
			try	{	list_snapshot_packet_count_tuples = (LinkedList<Tuple>) SOURCE.tree_snapshot_packet_count.values();	}	
			catch(Exception e)
			{
				list_snapshot_packet_count_tuples = new LinkedList<Tuple>(SOURCE.tree_snapshot_packet_count.values());
			}
			
			//sort the list
			Collections.sort(list_snapshot_packet_count_tuples, new Comparator<Tuple>()
			{
				public int compare(Tuple t1, Tuple t2)
				{
					return t2.value - t1.value;
				}						
				
			});
			
			index_snapshot = 0;
			for(Tuple tuple : list_snapshot_packet_count_tuples)
			{
				try
				{
					snapshot_packet_names[index_snapshot] = tuple.name;
					snapshot_packet_vals[index_snapshot] = tuple.value;
					
					//reset snapshot val
					tuple.value = 0;
					
					++index_snapshot;					
					if(index_snapshot >= snapshot_packet_names.length)
						break;
				}
				catch(Exception ee)
				{
					++index_snapshot;
					continue;
				}
			}
			/*for(String key : SOURCE.tree_snapshot_packet_count.keySet())
			{
				try
				{
					snapshot_packet_names[index_snapshot] = key;
					snapshot_packet_vals[index_snapshot] = SOURCE.tree_snapshot_packet_count.get(key);
					
					//reset snapshot val
					SOURCE.tree_snapshot_packet_count.put(key,0);
					
					++index_snapshot;					
					if(index_snapshot >= snapshot_packet_names.length)
						break;
				}
				catch(Exception ee)
				{
					++index_snapshot;
					continue;
				}
			}*/											
			
			//update
			line_packet_snapshot.display_data(snapshot_packet_names, snapshot_packet_vals);
			
			i_am_updating_summary = false;
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "update_packet_summary_snapshot", e);
		}
		
		i_am_updating_summary = false;
		
		return false;
	}
	
	public boolean configure_signature_panel(JTextArea_Solomon jta)
	{
		try
		{
			if(jta == null)
				return false;
			
			jta.populate_console_buttons(true, true, false, false, true, false);
			
			//handle the button presses here
			jta.jbtnSend.removeActionListener(jta);
			jta.jtf.removeActionListener(jta);
			jta.jbtnClear.removeActionListener(jta);
			
			jta.jbtnSend.addActionListener(this);
			jta.jtf.addActionListener(this);
			jta.jbtnClear.addActionListener(this);
			
			this.jtbl_ALERTS.jcbRejectUpdate.setVisible(false);
			this.jtbl_ALERTS.jbtnClearAndRefresh.setVisible(false);
			this.jtbl_ALERTS.jtfFilter.setVisible(false);
			this.jtbl_ALERTS.jpnlSouth.setVisible(false);
			
			this.jfrm.validate();
			this.jtbl_ALERTS.validate();
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "configure_signature_panel", e);
		}
		
		return false;
	}
	
	public boolean configure_jtblResolution()
	{
		try
		{
						
			//handle the button presses here
			jtblResolution.jbtnClearAndRefresh.removeActionListener(jtblResolution);
			jtblResolution.jtfFilter.removeActionListener(jtblResolution);
			jtblResolution.jtfMaxRowCount.removeActionListener(jtblResolution);
			
			jtblResolution.jbtnClearAndRefresh.addActionListener(this);
			jtblResolution.jtfFilter.addActionListener(this);
			jtblResolution.jtfMaxRowCount.addActionListener(this);
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "configure_jtblResolution", e);
		}
		
		return false;
	}
	
	public boolean configure_jtblCookies_NetworkCapture()
	{
		try
		{
						
			//handle the button presses here
			this.jtblCookies_NetworkCapture.jbtnClearAndRefresh.removeActionListener(jtblResolution);
			jtblCookies_NetworkCapture.jtfFilter.removeActionListener(jtblResolution);
			jtblCookies_NetworkCapture.jtfMaxRowCount.removeActionListener(jtblResolution);
			
			jtblCookies_NetworkCapture.jbtnClearAndRefresh.addActionListener(this);
			jtblCookies_NetworkCapture.jtfFilter.addActionListener(this);
			jtblCookies_NetworkCapture.jtfMaxRowCount.addActionListener(this);
			
			jtblCookies_NetworkCapture.jlblFilter.setVisible(false);
			jtblCookies_NetworkCapture.jtfFilter.setVisible(false);
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "configure_cookies", e);
		}
		
		return false;
	}
	
	public boolean configure_jtblApplicationCategorization()
	{
		try
		{
						
			//handle the button presses here
			this.jtblApplicationCategorization_out.jbtnClearAndRefresh.removeActionListener(jtblResolution);
			jtblApplicationCategorization_out.jtfFilter.removeActionListener(jtblResolution);
			jtblApplicationCategorization_out.jtfMaxRowCount.removeActionListener(jtblResolution);
			
			jtblApplicationCategorization_out.jbtnClearAndRefresh.addActionListener(this);
			jtblApplicationCategorization_out.jtfFilter.addActionListener(this);
			jtblApplicationCategorization_out.jtfMaxRowCount.addActionListener(this);
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "configure_jtblApplicationCategorization", e);
		}
		
		return false;
	}
	
	public boolean close()
	{
		try
		{
			if(driver.query_user("Close " + Driver.NAME, "Exit?") == JOptionPane.YES_OPTION)
			{
				
				if(driver.isWindows)
				{
					try	{	Process p = Runtime.getRuntime().exec("cmd.exe /C " + "\"" + "taskkill /f /im tshark*" + "\"");	}	catch(Exception e){}
					try	{	Process p = Runtime.getRuntime().exec("cmd.exe /C " + "\"" + "taskkill /f /im dumpcap*" + "\"");	}	catch(Exception e){}
				}
				else if(driver.isLinux)
				{
					//String [] cmd = new String [] {"/bin/bash", "-c", SENSOR_COMMAND};
					//Process p = Runtime.getRuntime().exec(cmd);					
				}
				
				driver.directive("Program Terminated.");
				System.exit(0);
			}
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "close", e);
		}
		
		return false;
	}
	
	
	public static boolean update_jtblNetworkMap()
	{
		try
		{
			StandardInListener.intrface.jtblNetworkMap.removeAllRows();
			
			if(Node_NMap.TREE_NMAP_NODES == null || Node_NMap.TREE_NMAP_NODES.isEmpty())
				return false;
			
			for(Node_NMap node : Node_NMap.TREE_NMAP_NODES.values())
			{
				StandardInListener.intrface.jtblNetworkMap.addRow(node.get_jtable_row());				
			}
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "update_jtblNetworkMap", e);
		}
		
		return false;
	}
	
	
	
	public static boolean update_jtblOUI_in_use()
	{
		try
		{
			if(StandardInListener.intrface.jtblOUI_In_Use.jcbRejectUpdate != null && StandardInListener.intrface.jtblOUI_In_Use.jcbRejectUpdate.isSelected())
				return false;
			
			StandardInListener.intrface.jtblOUI_In_Use.removeAllRows();
			
			/*if(Node_OUI.tree_oui_in_use == null || Node_OUI.tree_oui_in_use.isEmpty())
				return false;
			
			for(Node_OUI node : Node_OUI.tree_oui_in_use.values())
			{
				StandardInListener.intrface.jtblOUI_In_Use.addRow(node.get_jtable_row());				
			}*/
			
			if(Node_OUI_Container_GUI.TREE_OUI_COMPANY_NAME == null || Node_OUI_Container_GUI.TREE_OUI_COMPANY_NAME.isEmpty())
				return false;
			
			for(Node_OUI_Container_GUI container : Node_OUI_Container_GUI.TREE_OUI_COMPANY_NAME.values())
			{
				if(container == null)
					continue;
				
				StandardInListener.intrface.jtblOUI_In_Use.addRow(container.get_jtable_row());
			}
			
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "update_jtblOUI_in_use", e);
		}
		
		return false;
	}
	
	public void actionPerformed(ActionEvent ae)
	{
		try
		{
			if(ae.getSource() == jmnuitm_Close)
			{
				close();
			}						
			
			else if(ae.getSource() == this.jbtnImportNetworkMapFile)
			{
				NMap nmap = new NMap(null);
			}
			
			else if(ae.getSource() == jrbNetworkMapDisabled)
			{
				StandardInListener.set_nmap_enabled(false);
			}
			
			else if(ae.getSource() == jrbNetworkMapEnabled)
			{
				StandardInListener.set_nmap_enabled(true);
			}
			
			else if(ae.getSource() == this.jmnuitm_Import)
			{
				//try{	ThreadSound.play(ThreadSound.url_note_beep);	}	catch(Exception ee){}
				
				File fle = driver.querySelectFile(true, "Please select file to import", JFileChooser.FILES_ONLY, false, false);
				
				if(fle == null || !fle.exists() || !fle.isFile())
				{
					driver.directive("\nPUNT! No valid file selected!");
					driver.jop_Error("PUNT! No valid file selected!", true);
				}
				
				else
					StandardInListener.import_file(fle);
			}
			
			if(ae.getSource() == jtblOUI_In_Use.jbtnClearAndRefresh)
			{
				this.update_jtblOUI_in_use();
			}
			
			else if(ae.getSource() == jtblNetworkMap.jbtnClearAndRefresh)
			{
				update_jtblNetworkMap();
			}
			
			else if(ae.getSource() == jtblCookies_HostSystem.jbtnClearAndRefresh)
			{
				StandardInListener.update_cookies_host_system(true);
			}
			
			else if(ae.getSource() == pie_RESOURCE_statistics_EXTERNAL.jbtnUpdateChart)
			{								
				if(StandardInListener.intrface == null || Resolution.TREE_RESOURCE == null || Resolution.TREE_RESOURCE.isEmpty())
				{
					driver.jop_Error("There are no resources populated in the system yet...", false);
				}
				else				
				{
					StandardInListener.update_PIE_resource_statistics_EXTERNAL(true);
				}
			}
			
			else if(ae.getSource() == pie_devices_on_network.jbtnUpdateChart)
			{								
				if(StandardInListener.intrface == null || Node_OUI_Container_GUI.TREE_OUI_COMPANY_NAME == null || Node_OUI_Container_GUI.TREE_OUI_COMPANY_NAME.isEmpty())
				{
					driver.jop_Error("Punt! There are no devices populated in the system yet...", false);
				}
				else				
				{
					Node_OUI_Container_GUI.update_names_and_values();
					StandardInListener.intrface.pie_devices_on_network.display_data(Node_OUI_Container_GUI.arrNames, Node_OUI_Container_GUI.arrValues, true);
				}
			}
			
			else if(ae.getSource() == bar_devices_on_network.jbtnUpdateChart)
			{								
				if(StandardInListener.intrface == null || Node_OUI_Container_GUI.TREE_OUI_COMPANY_NAME == null || Node_OUI_Container_GUI.TREE_OUI_COMPANY_NAME.isEmpty())
				{
					driver.jop_Error("Punt! There are no devices populated in the system yet...", false);
				}
				else				
				{
					Node_OUI_Container_GUI.update_names_and_values();
					StandardInListener.intrface.bar_devices_on_network.display_data(Node_OUI_Container_GUI.arrNames, Node_OUI_Container_GUI.arrValues);
				}
			}
			
			else if(ae.getSource() == pie_RESOURCE_statistics_INTERNAL.jbtnUpdateChart)
			{								
				if(StandardInListener.intrface == null || Resolution.TREE_RESOURCE == null || Resolution.TREE_RESOURCE.isEmpty())
				{
					driver.jop_Error("Punt! There are no resources populated in the system yet...", false);
				}
				else				
				{
					StandardInListener.update_PIE_resource_statistics_INTERNAL(true, true);
				}
			}
			
			else if(ae.getSource() == bar_RESOURCE_statistics_EXTERNAL.jbtnUpdateChart)
			{								
				if(StandardInListener.intrface == null || Resolution.TREE_RESOURCE == null || Resolution.TREE_RESOURCE.isEmpty())
				{
					driver.jop_Error("There are no resources populated in the system yet...", false);
				}
				else				
				{
					StandardInListener.update_BAR_resource_statistics_EXTERNAL();
				}
			}
			
			else if(ae.getSource() == bar_RESOURCE_statistics_INTERNAL.jbtnUpdateChart)
			{								
				if(StandardInListener.intrface == null || Resolution.TREE_RESOURCE == null || Resolution.TREE_RESOURCE.isEmpty())
				{
					driver.jop_Error("Punt!!! There are no resources populated in the system yet...", false);
				}
				else				
				{
					StandardInListener.update_BAR_resource_statistics_INTERNAL();
				}
			}
			
			
			else if(ae.getSource() == this.jrbEncryptionDisabled)
			{
				StandardInListener.set_encryption(null);				
			}
			
			else if(ae.getSource() == bar_NODE_statistics.jbtnUpdateChart)
			{
				if(StandardInListener.selected_node_to_monitor == null)
				{
					driver.jop_Error("NOTE! You need to select a valid node from Source Nodes first...", "Node not selected yet...");
				}
				else					
					StandardInListener.update_selected_node_statistics();
			}
			
			else if(ae.getSource() == pie_NODE_statistics.jbtnUpdateChart)
			{
				if(StandardInListener.selected_node_to_monitor == null)
				{
					driver.jop_Error("NOTE! You need to select a valid node from Source Nodes first...", "Node not selected yet...");
				}
				else					
					StandardInListener.update_selected_node_statistics();
			}
						
			else if(ae.getSource() == jbtnMonitorInSummary)
			{
				StandardInListener.monitor_selected_node_in_network_summary();
			}
			
			else if(ae.getSource() == jmnuitem_MonitorInSummary)
			{
				StandardInListener.monitor_selected_node_in_network_summary();
			}
			
			else if(ae.getSource() == bar_network_statistics.jbtnUpdateChart)
			{
				StandardInListener.update_BAR_overall_network_statistics();
			}
			
			else if(ae.getSource() == pie_network_statistics.jbtnUpdateChart)
			{
				StandardInListener.update_PIE_overall_network_statistics(true);
			}
			
			else if(ae.getSource() == this.jrbEncryptionEnabled)
			{
				String key = driver.jop_Query("Please specify encryption key", "Enter Encryption Key");
				
				if(key == null || key.trim().equals("") || key.equalsIgnoreCase("null"))
				{
					jrbEncryptionDisabled.setSelected(true);
					StandardInListener.set_encryption(null);
				}
				else
				{
					StandardInListener.set_encryption(key);	
				}												
			}
			
			else if(jpnlSignature != null && ae.getSource() == this.jpnlSignature.jbtnSend && !jpnlSignature.jtf.getText().trim().equals(""))
			{
				jpnlSignature.jta.append(jpnlSignature.jtf.getText().trim() + "\n");
				jpnlSignature.jtf.setText("");
			}
			
			else if(jpnlSignature != null && ae.getSource() == this.jpnlSignature.jtf && !jpnlSignature.jtf.getText().trim().equals(""))
			{
				jpnlSignature.jta.append(jpnlSignature.jtf.getText().trim()  + "\n");
				jpnlSignature.jtf.setText("");
			}
			
			else if(jpnlSignature != null && ae.getSource() == this.jpnlSignature.jbtnClear)
			{
				if(driver.jop_Query_Custom_Buttons("Are you sure you wish to clear all loaded signatures?", "Confirm Clear Signatures", new Object[]{"Clear Signatures", "Cancel"}) == 0)
				{
					jpnlSignature.jta.setText("");
					jpnlSignature.jtf.setText("");
				}
			}
			
			else if(ae.getSource() == jtblResolution.jbtnClearAndRefresh)
			{
				StandardInListener.update_jtbl_resolution(true);
			}
			
			else if(ae.getSource() == this.jtblResolution.jtfFilter )
			{
				executeFilterAction_jtblResolution(null, null);
			}
			
			else if(ae.getSource() == this.jtblCookies_NetworkCapture.jtfFilter )
			{
				//executeFilterAction_jtblCookies(jtblCookies, null, null);
			}
			
			else if(ae.getSource() == jtblApplicationCategorization_out.jbtnClearAndRefresh)
			{
				StandardInListener.update_jtbl_application(true);
			}
			
			else if(ae.getSource() == this.jtblCookies_NetworkCapture.jbtnClearAndRefresh)
			{
				StandardInListener.update_jtbl_cookies();
			}
				
			
			this.jfrm.validate();
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "ae", e);
		}
	}//end ae
	
	
	
	public boolean executeFilterAction_jtblResolution(String filter_key, String filter_value)
	{
		try
		{		
			
			
			//update keys if necessary
			if(filter_key == null || filter_key.trim().equals(""))
			{
				//try to get what is currently selected 
				filter_key = ""+this.jtblResolution.jcbSortTableBy.getSelectedItem();
				
				//ensure valid key
				if(filter_key == null || filter_key.trim().equals(""))
				{
					driver.jop_Error("I am unable to acquire appropriate filter key. \nPlease select \"Sort By...\" specification to continue...", true);
					return false;
				}
			}
			
			//trim
			filter_key = filter_key.trim();
			
			//update value if necessary
			if(filter_value == null || filter_value.trim().equals(""))
			{
				filter_value = this.jtblResolution.jtfFilter.getText().trim();
				
				//ensure proper value
				if(filter_value == null || filter_value.trim().equals(""))
				{
					//just refresh
					StandardInListener.update_jtbl_resolution(true);
					return false;
				}
			}
			
			//trim
			filter_value = filter_value.trim();
			
			//indicate gui should proceed
			this.jtblResolution.jcbRejectUpdate.setSelected(false);
			
			//this will change based on the program, but we'll put the call here to actually put in the search below
			filter_jtblResolution(filter_key, filter_value, Resolution.TREE_RESOURCE, true);
			//filter_jtblResolution(filter_key, filter_value, Resolution.tree_unresolved_request, false);
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "executeFilterAction_jtblResolution", e);
		}
		
		return false;
	}
	
	
	
	public boolean filter_jtblResolution(String Filter_Key, String Filter_Value, TreeMap<String, Resolution> tree, boolean clear_all_rows)
	{
		try
		{
			//ready to filter, remove all nodes previously			
			if(clear_all_rows)
				try	{	jtblResolution.removeAllRows();	}	catch(Exception e){}
			
			if(tree == null || tree.isEmpty())
				return false;
			
			if(Filter_Key == null || Filter_Key.trim().equals(""))
				return false;
			
			if(Filter_Value == null || Filter_Value.trim().equals(""))
				return false;
			
			if(jtblResolution.jcbRejectUpdate.isSelected())
				return false;
			
			try	{	included_node.clear();} catch(Exception e){included_node = new TreeMap<String, Resolution>();}
			
			//execute search on each node
			for(Resolution node : tree.values())
			{
				if(node == null)
					continue;
					
				//get actual value from the node
				jtblResolution.value_node = node.get(Filter_Key, Filter_Value);
				
				//driver.jop(node.address + "\n" + "Key: " + Filter_Key + "\n" + "Filter Value: " + Filter_Value +  "\nReturned Value: " + jtblResolution.value_node + "\n" + "result:" + (jtblResolution.value_node != null && !jtblResolution.value_node.trim().equals("")));
				
				if(jtblResolution.value_node != null && !jtblResolution.value_node.trim().equals(""))
				{
					//ensure we haven't already added it
					if(included_node.containsKey(node.address))
						continue;
					
					jtblResolution.addRow(node.get_jtable_row_summary("\t", false));
					
					included_node.put(node.address, node);
				}
			}
			
			//sort
			jtblResolution.sortJTable_ByRows(jtblResolution.dfltTblMdl, jtblResolution.jcbSortTableBy.getSelectedIndex(), jtblResolution.sortInAscendingOrder);
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "filter_jtblResolution", e);
		}
		
		return false;
	}
	
	

	
	public static boolean displaySelectedRowInDataView_resolution(String key)
	{
		try
		{
			if(StandardInListener.intrface == null)
				return false;
			
			if(key == null || key.trim().equals(""))
			{
				driver.jop_Error("Sorry! Key [" + key + "] was not found!", false);
				return false;
			}
			
			key = key.toLowerCase().trim();
			displayString_resolution = "";
			resolution_data_view = null;
			
			if(Resolution.TREE_RESOURCE.containsKey(key))
				resolution_data_view = Resolution.TREE_RESOURCE.get(key);
			else if(Resolution.tree_unresolved_request.containsKey(key))
				resolution_data_view = Resolution.tree_unresolved_request.get(key);
			
			
			if(resolution_data_view == null)
			{
				driver.directive("PUNT! I was unable to find key[ " + key + "] in the tree of resolved or unresolved resource requests...");
				return false;
			}
			
			StandardInListener.intrface.jtblResolution.jta.clear();
			
			displayString_resolution = resolution_data_view.getDataViewInformation("\n");
					
			StandardInListener.intrface.jtblResolution.jta.append(displayString_resolution);
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "displaySelectedRowInDataView_resolution", e);
		}
		
		return false;
	}
	
	
	public boolean displaySelectedRowInDataView_cookies_host_system(int row_selected)
	{
		try
		{
			if(row_selected < 0 || Cookie_Object_Host_System.list_cookie_object_host_system == null || Cookie_Object_Host_System.list_cookie_object_host_system.isEmpty())
				return false;
			
			LinkedList<Cookie_Object_Host_System> list_cookies = new LinkedList<Cookie_Object_Host_System>();
			
			//Get the specific node selected
			String cookie_value = ""+this.jtblCookies_HostSystem.dfltTblMdl.getValueAt(row_selected, 7);
			String path  = ""+this.jtblCookies_HostSystem.dfltTblMdl.getValueAt(row_selected, 16);
			
			//add the first one
			for(Cookie_Object_Host_System cookie : Cookie_Object_Host_System.list_cookie_object_host_system)
			{
				if(cookie == null)
					continue;
				
				if(cookie.cookie_value != null && cookie.cookie_value.equalsIgnoreCase(cookie_value) && cookie.file_path != null && cookie.file_path.equalsIgnoreCase(path))
				{
					list_cookies.add(cookie);
					break;
				}
			}			
			
			//populate with remaining nodes						
			for(Cookie_Object_Host_System cookie : Cookie_Object_Host_System.list_cookie_object_host_system)
			{
				if(cookie == null)
					continue;
				
				if(list_cookies.contains(cookie))
					continue;
				
				if(cookie.file_path != null && cookie.file_path.equalsIgnoreCase(path))
				{
					list_cookies.add(cookie);
				}
			}
			
			//check
			if(list_cookies == null || list_cookies.isEmpty())
				return false;
			
			//enter the first contents
			this.jtblCookies_HostSystem.jta.append(list_cookies.getFirst().get_display_data("\n"));
			
			if(Cookie_Object_Host_System.list_cookie_object_host_system.size() > 1)
			{
				this.jtblCookies_HostSystem.jta.append("\nAdditional Cookies within File:\n");
				
				for(int i = 1; i < list_cookies.size(); i++)
				{
					this.jtblCookies_HostSystem.jta.append("\n====================================================\n");
					this.jtblCookies_HostSystem.jta.append(list_cookies.get(i).get_display_data("\n"));
				}
			}
			

			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "displaySelectedRowInDataView_cookies_host_system", e);
		}
		
		return false;
	}
	
	
	public boolean displaySelectedRowInDataView_network_map(int row_selected)
	{
		try
		{
			if(row_selected < 0 || Node_NMap.TREE_NMAP_NODES == null || Node_NMap.TREE_NMAP_NODES.isEmpty())
				return false;
			
			
			//Get the specific node selected
			selected_value = ""+this.jtblNetworkMap.dfltTblMdl.getValueAt(row_selected, 0);
			
			if(Node_NMap.TREE_NMAP_NODES.containsKey(selected_value))
			{
				this.jtblNetworkMap.jta.clear();
				this.jtblNetworkMap.jta.append(Node_NMap.TREE_NMAP_NODES.get(selected_value).get_data_row_summary("\n"));
			}
			

			return true;
		}
		catch(Exception e)
		{
			//driver.eop(myClassName, "displaySelectedRowInDataView_network_map", e);
			driver.directive("no data found for node: " + selected_value);
		}
		
		return false;
	}
	
	public boolean displaySelectedRowInDataView_oui_in_use(int row_selected)
	{
		try
		{
			if(row_selected < 0 || Node_OUI.tree_oui_in_use == null || Node_OUI.tree_oui_in_use.isEmpty())
				return false;
			
			
			//Get the specific node selected
			selected_value = ""+this.jtblOUI_In_Use.dfltTblMdl.getValueAt(row_selected, 0);
			
			/*selected_value = driver.strip_MAC(selected_value);
			
			if(Node_OUI.tree_oui_in_use.containsKey(selected_value))
			{
				this.jtblOUI_In_Use.jta.clear();
				this.jtblOUI_In_Use.jta.append(Node_OUI.tree_oui_in_use.get(selected_value).get_data_row_summary("\n"));
			}*/
			
			if(Node_OUI_Container_GUI.TREE_OUI_COMPANY_NAME.containsKey(selected_value))
			{
				this.jtblOUI_In_Use.jta.clear();
				this.jtblOUI_In_Use.jta.append(Node_OUI_Container_GUI.TREE_OUI_COMPANY_NAME.get(selected_value).get_data_row_summary("\n"));
			}
			

			return true;
		}
		catch(Exception e)
		{
			//driver.eop(myClassName, "displaySelectedRowInDataView_oui_in_use", e);
			driver.directive("no data found for node: " + selected_value);
		}
		
		return false;
	}
	
	
	public static boolean displaySelectedRowInDataView_application(String key)
	{
		try
		{
			if(StandardInListener.intrface == null)
				return false;
			
			if(key == null || key.trim().equals(""))
			{
				driver.jop_Error("Sorry!!! Key [" + key + "] was not found!", false);
				return false;
			}
			
			key = key.toLowerCase().trim();
			application_display_string = "";
			application_search = null;
			
			if(Application.TREE_APPLICATION.containsKey(key))
				application_search = Application.TREE_APPLICATION.get(key);
						
			
			if(application_search == null)
			{
				driver.directive("PUNT!!!! I was unable to find key[" + key + "] in the tree of applications...");
				return false;
			}
			
			StandardInListener.intrface.jtblApplicationCategorization_out.jta.clear();
			
			application_display_string = application_search.getDataViewInformation();
					
			StandardInListener.intrface.jtblApplicationCategorization_out.jta.append(application_display_string);
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "displaySelectedRowInDataView_application", e);
		}
		
		return false;
	}
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
}
