package Interface;
/**

 * This class will contain all code to establish the JTable to include the panel containing the JTable 
 * 
 * You are free to use this code.  Only stipulation: leave author information
 * 
 * @author Solomon Sonya 
 */


import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Font;
import java.net.Socket;
import java.security.MessageDigest;
import java.text.SimpleDateFormat;
import java.util.*;
import java.awt.*;
import java.awt.event.*;
import java.io.*;
import Driver.*;
import javax.swing.border.BevelBorder;
import javax.swing.border.TitledBorder;
import javax.swing.event.*;
import javax.swing.*;
import javax.swing.Timer;
import javax.swing.table.*;

import Encryption.Encryption;
import Profile.SOURCE;
//import Sound.ThreadSound;



public class JTable_Solomon extends JPanel implements ItemListener, ActionListener, ListSelectionListener, MouseListener
{
	public static final String myClassName = "JTable_Solomon";
	public static final String VERSION = "2.005";
	public static Driver driver = new Driver();
	public volatile int selectedRow = 0, selectedCol = 0;
	public volatile Object selectedField = "";
	public volatile boolean load_list = false;
	
	public volatile Vector vctColToolTips = null;
	public volatile Vector vctColNames = null;
	
	public volatile String FILTER_KEY = "";
	public volatile String FILTER_VALUE = "";
	public volatile String value_node = "";
	
	public volatile static LinkedList<JTable_Solomon> list_JTables = new LinkedList<JTable_Solomon>();
	
	public volatile Vector v1 = null, v2 = null;
	public volatile Object o1 = null, o2 = null;
	
	public DefaultTableModel dfltTblMdl;
	
	public volatile JPopupMenu jpopup_SelectedRow = null, jpopup_EmptySpace_NoRowsSelected = null;
	public volatile JMenuItem jmnuitm_CopyToClipboard = null;
	public volatile JMenuItem jmnuitm_AddToFilter = null, jmnuitm_DisplayInDataViewPane = null, jmnuitm_ClearFilter = null, jmnuitm_ClearFilter_NoRowSelected = null;
	
	//JPanel jpnlMain = new JPanel(new BorderLayout());
	
	public volatile JPanel jpnlJTable = new JPanel();//to hold the ScrollPane
	
	public volatile JTable jtblMyJTbl = null;
	public volatile JTableHeader header_jtable = null;
	public volatile JScrollPane jscrlpneJTable;
	
	public volatile 	JPanel jpnl_jcbSortTableBy = new JPanel(new BorderLayout());
	public volatile 	JPanel jpnlSortOptions = new JPanel();
	public volatile 		JLabel jlblSortBy = new JLabel("Sort By..." ,  JLabel.LEFT);
			public JComboBox jcbSortTableBy = null;
			public volatile 		JCheckBox jcbSortInAscendingOrder = new JCheckBox("Sort in Ascending Order", true);
			public boolean sortInAscendingOrder = true;
			
	
			
			
	public JPanel jpnlSouth = new JPanel(new GridLayout(1,4));
	public volatile 		JPanel jpnlAddToFilter = new JPanel(new GridLayout(1,1));
	public volatile 		JLabel jlblAddSelectedRowToFilter_1 = new JLabel("Add Selected ");
	public volatile 		JLabel jlblAddSelectedRowToFilter_2 = new JLabel(" to filter... ");
			public volatile 		JComboBox jcbAddToFilter = null;
			public volatile 		JButton jbtnAddToFilter = null;
			public volatile 		JButton jbtnDisplayInDataView = null;
			
	public JPanel jpnlNumRows = new JPanel();
	public volatile 	JLabel jlblNumRows_Text = new JLabel("Num Rows Populated: " , JLabel.LEFT);
	public volatile 	JLabel jlblNumRows = new JLabel("0", JLabel.LEFT);
		
		public JButton jbtnGoogleMap = new JButton("Google Map");//Dummy button for this widget.  It's action performed will be caught by a different class chosen by the program. I know, nice huh???  //Solomon 2013-01-26
		public JButton jbtnClearAndRefresh = new JButton("Clear and Refresh");		
		public JButton jbtnSetEncryptionKey = new JButton("Set Encryption Key");
		public JButton jbtnDisconnectAgent = new JButton("Disconnect Agent");
		
		private JPanel jpnlNorth_Heading = new JPanel(new GridLayout(2,1));
		public JLabel jlblHeading = null;
		
		public volatile boolean updateJTable = false;
		public Timer tmrUpdateJTable = new Timer(50, this);
		
		public Color clrDefaultBackground = Color.white;
		public Color clrDefaultForeground = Color.black;
		
		public JCheckBox jcbRejectUpdate = new JCheckBox("Reject Update");
		
		public JLabel jlblFilter = new JLabel("Filter: ");
		public JTextField jtfFilter = new JTextField(20); 
		public volatile String filter = "";
		public volatile int filter_col_index = 0;
		
		public JLabel jlblMaxRowCount = new JLabel("Max Row Count: ");
		public JTextField jtfMaxRowCount = new JTextField(4);
		public volatile int maxRowCount = 1000;
		
		public volatile JButton jbtnExportTable = new JButton("Export Table");
		
		public volatile JCheckBox jcbDisableAgentUpdates = new JCheckBox("Disable Agent Updates", false);
		
		public String myTitle = "";
		
	//Leaving out Sorting options for now
	
	//Leaving out Number of Rows and Cols populated for now
		
	public volatile Object objValue = "";
	public volatile String displayString = "";
		
	Vector vctTblData;
	
	boolean acceptComponent = true;
	
	JButton jbtnSetThreshold = new JButton("Set Threshold");	
	public volatile int index = 0;
	public volatile JPanel jpnlNotificationPane = new JPanel(new BorderLayout());
	public volatile JPanel jpnlJCB = new JPanel(new BorderLayout());
	public volatile JPanel jpnlNotification_South = new JPanel(new GridLayout(1,1,2,2));
	public volatile JLabel jlblData = new JLabel("                    Data:                    ", JLabel.CENTER);
	public volatile JTextArea_Solomon jta = new JTextArea_Solomon("", false, "", false);		
	public volatile JSplitPane_Solomon jspltpne = null;
	public volatile double threshold = 10;
	
	public volatile boolean useHashTable_MAC = false, useHashTable_SSID = false, useHathTable_GEO = false, useHashTable_AccessPoint = false;
	
	
	public volatile int rowSelected = 0, colSelected = 0;
	
	boolean include_Server_Socket_Connection_Area = false;
	
	public volatile JPanel jpnlHEADING = new JPanel(new BorderLayout());
	
	public volatile JPanel jpnlCONNECTION_CONTAINER = new JPanel(new GridLayout(1,2,2,2));
		
		public volatile JPanel jpnlConnectionInformation = new JPanel(new BorderLayout());
			public volatile JTextField jtfAddress = new JTextField(12);
			//public volatile JPanel jpnlNorthButtons = new JPanel(new GridLayout(1,7, 2, 2));
			public volatile JPanel jpnlNorthButtons = new JPanel();
				public volatile JButton jbtnListen = new JButton("Listen");
				public volatile JButton jbtnConnect = new JButton("Connect");
				public volatile JButton jbtnDisconnectAll = new JButton("Disconnect All ");
				public volatile JLabel jlblNumConnectedSockets = new JLabel("0", JLabel.CENTER);
				
		public volatile JPanel jpnlEncryption = new JPanel(new BorderLayout());
			public volatile JTextField jtfEncryption_key_AES = new JTextField(12);
			public volatile JPanel jpnlEncryptionButtons = new JPanel(new GridLayout(1,4, 2, 2));
				public volatile ButtonGroup bg = new ButtonGroup();
					public volatile JCheckBox jcbAgentResponseEnabled = new JCheckBox("Enable Agent Communication", true);
					public volatile JCheckBox jcbEncryptionEnabled = new JCheckBox("Encryption ON");
					public volatile JCheckBox jcbEncryptionDisabled = new JCheckBox("Encryption OFF", true);
					public volatile JLabel jlblEncryptionStatus = new JLabel("Encryption: [DISABLED]", JLabel.CENTER);
				
					MessageDigest messageDigest = null;
					public volatile String key = "";
					public static final String default_iv_value = Encryption.default_iv_value;
					public static volatile Encryption myEncryption = null;
					
					
					public volatile boolean is_jpnlSouth_visible_initial_visibility = true; 
					
		public String specific_options_border_title = "";			
					
	public volatile boolean process_double_click_for_resolution = false;
	public volatile boolean process_double_click_for_application = false;
	public volatile boolean process_double_click_for_cookies_network_capture = false;
	public volatile boolean process_double_click_for_cookies_host_system = false;
	public volatile boolean process_double_click_for_network_map = false;
	public volatile boolean process_double_click_for_update_oui_list = false;
	
	
	
	/**
	 * null is acceptable for the Background color.. this simply means it will not be set to anything
	 * 
	 * @param vColNames
	 * @param vToolTips
	 * @param headingTitle
	 * @param titleForeground
	 * @param titleBackground
	 */
	public JTable_Solomon(Vector vColNames, Vector vToolTips, String headingTitle, Color titleForeground, Color titleBackground)
	{
		try
		{
			//this.setBackground(Color.RED);
			try
			{
				myTitle = headingTitle;
				jlblHeading = new JLabel(headingTitle, SwingConstants.CENTER);				
				jlblHeading.setForeground(titleForeground);
												
				if(titleForeground == null)
					titleForeground = Color.blue.darker();
				
				if(titleBackground != null)
				{
					jlblHeading.setOpaque(true);
					jlblHeading.setBackground(titleBackground);
				}
				jlblHeading.setFont(new Font("Courier", Font.BOLD, 18));
				//jpnlNorth_Heading.add(jlblHeading);
			}catch(Exception e){}
			
			initializeJTable(vColNames, vToolTips);
			initializeGUI(vColNames);
			
			//start a timer to update the jtable as well
			try{	tmrUpdateJTable.start();	}	catch(Exception e){}
			
			
			
		}//end entire try for constructor mtd
		catch(Exception e)
		{
			driver.eop(myClassName, "Constructor - 1", e);
		}
		
	}//end constructor
	
	public JTable_Solomon(boolean includeServerSocketConnectionArea, String [] ColNames, String [] ToolTips, String headingTitle, Color titleForeground, Color titleBackground, boolean setColumnAutoSize, int preferredColWidth, String options_title_OPTIONAL, boolean is_jpnlSouth_Visible, int rows_in_new_south_panel)
	{
		try
		{
			//this.setBackground(Color.RED);
			try
			{
				myTitle = headingTitle;
				jlblHeading = new JLabel(headingTitle, SwingConstants.CENTER);				
				jlblHeading.setForeground(titleForeground);
				include_Server_Socket_Connection_Area = includeServerSocketConnectionArea;
				
				
				is_jpnlSouth_visible_initial_visibility = is_jpnlSouth_Visible;
				
				if(titleForeground == null)
					titleForeground = Color.blue.darker();
				
				if(titleBackground != null)
				{
					jlblHeading.setOpaque(true);
					jlblHeading.setBackground(titleBackground);
				}
				jlblHeading.setFont(new Font("Courier", Font.BOLD, 18));
				
				if(rows_in_new_south_panel > 1)
					jpnlNotification_South = new JPanel(new GridLayout(rows_in_new_south_panel,1,2,2));		
				else
					jpnlNotification_South = new JPanel(new GridLayout(1,1,2,2));
				
				//jpnlNorth_Heading.add(jlblHeading);
			}catch(Exception e){}
			
			Vector vColNames = new Vector();
			vColNames.addAll(Arrays.asList(ColNames));
			
			Vector vToolTips = new Vector();
			vToolTips.addAll(Arrays.asList(ToolTips));
			
			if(options_title_OPTIONAL == null)
				this.specific_options_border_title = "";
			else
				this.specific_options_border_title = options_title_OPTIONAL;
			
			initializeJTable(vColNames, vToolTips);
			initializeGUI(vColNames);
			
			
			
			//start a timer to update the jtable as well
			try{	tmrUpdateJTable.start();	}	catch(Exception e){}
			
			if(setColumnAutoSize || (ColNames != null && ColNames.length < 10))
				this.jtblMyJTbl.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS);
			
			if(preferredColWidth > 0)
			{
				try	
				{
					for(int i = 0; i < this.jtblMyJTbl.getColumnCount(); i++)
						jtblMyJTbl.getColumnModel().getColumn(i).setPreferredWidth(preferredColWidth);
				}
				catch(Exception e){}	
			}
			
		}//end entire try for constructor mtd
		catch(Exception e)
		{
			driver.eop(myClassName, "Constructor - 1", e);
		}
		
		
		
	}//end constructor
	
	public boolean initializeGUI(Vector vColNm)
	{
		try
		{
			this.setLayout(new BorderLayout());
			
			//this.jscrlpneJTable = new JScrollPane(this.jtblMyJTbl);
			this.jcbSortTableBy = new JComboBox();
			jcbAddToFilter = new JComboBox();
			
			//Populate JComboBox
			for(int i = 0; i < vColNm.size(); i++)
			{
				this.jcbSortTableBy.addItem(vColNm.get(i));
				jcbAddToFilter.addItem(vColNm.get(i));
			}
			
			//Manual Resize Cols
			try
			{
				//this.jtblMyJTbl.getColumnModel().getColumn(0).setPreferredWidth(40);
				
			}
			catch(Exception e)
			{
				driver.sop("Could not resize cols. Not a critical error");
			}
			
			
			//Add JTable
			this.jscrlpneJTable = new JScrollPane(this.jtblMyJTbl);
			//this.add(this.jscrlpneJTable, BorderLayout.CENTER);
			
			this.jpnlNotificationPane.add(BorderLayout.NORTH, jlblData);
			this.jpnlNotificationPane.add(BorderLayout.CENTER, jta);
			
			
			
			this.jpnlNotificationPane.add(BorderLayout.SOUTH, jpnlNotification_South);
			
			jpnlJCB.add(BorderLayout.WEST, this.jta.jcbAutoScroll);
			jpnlJCB.add(BorderLayout.EAST, this.jta.jcbRejectUpdate);
			jpnlNotification_South.add(this.jpnlJCB);
			jpnlNotification_South.add(this.jta.jbtnExportData);
			jpnlNotification_South.add(this.jbtnExportTable);

			//this.jpnlNotificationPane.add(BorderLayout.SOUTH, this.jbtnSetThreshold);			
			jlblData.setBorder(new BevelBorder(BevelBorder.LOWERED, null, null, null, null));
			this.jspltpne = new JSplitPane_Solomon(JSplitPane.HORIZONTAL_SPLIT, this.jscrlpneJTable, this.jpnlNotificationPane, 1200);
			jbtnSetThreshold.addActionListener(this);		
			jta.jcbAutoScroll.setSelected(false);
			this.jtblMyJTbl.addMouseListener(this);
			this.add(this.jspltpne, BorderLayout.CENTER);
			
			jscrlpneJTable.addMouseListener(this);
			
			try	
			{	
				header_jtable = jtblMyJTbl.getTableHeader();
				header_jtable.addMouseListener(this);
				
			}catch(Exception e){}
			
			
			this.jta.restrict_data_entries = false;
			
			//jscrlpneJTable.setPreferredSize(new Dimension(1000, 1000));
			
			//Spacing on the right
			//this.add(new Label("  LEFT"), BorderLayout.WEST);
			
			//MouseAdapters not yet added...
			
			//Add Sorting Options
			jpnlSortOptions.add(this.jlblSortBy);
			jpnlSortOptions.add(this.jcbSortTableBy);
			jpnlSortOptions.add(this.jcbSortInAscendingOrder);
			jpnlSortOptions.add(this.jlblFilter);
			jpnlSortOptions.add(this.jtfFilter);
			jpnlSortOptions.add(this.jlblMaxRowCount);
			jpnlSortOptions.add(this.jtfMaxRowCount);
			
			
			
			jpnl_jcbSortTableBy.add(BorderLayout.NORTH, jlblHeading);
			jpnl_jcbSortTableBy.add(BorderLayout.SOUTH, new JLabel("  "));
			jpnl_jcbSortTableBy.add(jpnlSortOptions, BorderLayout.WEST);
			
			jpnl_jcbSortTableBy.setBorder(new TitledBorder(UIManager.getBorder("TitledBorder.border"), specific_options_border_title, TitledBorder.LEADING, TitledBorder.TOP, null, new Color(0, 51, 255)));
			
			if(include_Server_Socket_Connection_Area)
			{
				initizliaeSocketInterface();
				
				
				
				
			}
			else
			{
				this.add(this.jpnl_jcbSortTableBy, BorderLayout.NORTH);
				
			}
			
			
			
			
			
			
			//Row Counter
			
			
			//jpnlNumRows.add(jbtnDisconnectImplant);
			jpnlNumRows.add(jcbRejectUpdate);
			jpnlNumRows.add(jbtnGoogleMap);			jbtnGoogleMap.setVisible(false);
			jpnlNumRows.add(jbtnClearAndRefresh); //jbtnClear.setVisible(false);
			
			jpnlNumRows.add(jlblNumRows_Text);
			jpnlNumRows.add(jlblNumRows);
			jpnl_jcbSortTableBy.add(jpnlNumRows, BorderLayout.EAST);
			
			//jpnlSouth
			//jpnlSouth.add(jbtnAddToFilter);
			/*jpnlAddToFilter.add(jlblAddSelectedRowToFilter_1);
			jpnlAddToFilter.add(jcbAddToFilter);
			jpnlAddToFilter.add(jlblAddSelectedRowToFilter_2);*/
			jbtnAddToFilter = new JButton("Add Selected Field to Filter");
			jbtnDisplayInDataView = new JButton("Display Selected Row in Data View");
			jpnlSouth.add(jbtnAddToFilter);			
			jpnlSouth.add(jbtnSetEncryptionKey);
			jpnlSouth.add(jbtnDisconnectAgent);
			
				
				
			this.add(BorderLayout.SOUTH, this.jpnlSouth);
			
			//set visibility
			jpnlSouth.setVisible(is_jpnlSouth_visible_initial_visibility);
			
			
			//Validate GUI
			this.jtblMyJTbl.revalidate();
			this.jtblMyJTbl.repaint();
			this.validate();
			
			//Register Events
			this.jcbSortInAscendingOrder.addItemListener(this);
			this.jcbSortTableBy.addItemListener(this);
			jbtnAddToFilter.addActionListener(this);
			jbtnDisplayInDataView.addActionListener(this);
			jbtnSetEncryptionKey.addActionListener(this);
			jcbAddToFilter.addItemListener(this);
			jbtnDisconnectAgent.addActionListener(this);
			this.jtblMyJTbl.getSelectionModel().addListSelectionListener(this);
			jbtnClearAndRefresh.addActionListener(this);
			
			//Modify Widgets
			this.jlblSortBy.setForeground(new Color(0, 51, 255));
			jlblFilter.setForeground(new Color(0, 51, 255));
			jlblMaxRowCount.setForeground(new Color(0, 51, 255));
			this.jlblNumRows_Text.setForeground(new Color(0, 51, 255));
			
			this.setBorder(new TitledBorder(UIManager.getBorder("TitledBorder.border"), myTitle, TitledBorder.LEADING, TitledBorder.TOP, null, new Color(0, 51, 255)));

			this.jtfFilter.addActionListener(this);
			this.jtfMaxRowCount.addActionListener(this);
			jbtnExportTable.addActionListener(this);
			
			list_JTables.add(this);
			
			return true;
		}
		catch(Exception e)
		{
			//driver.eop("initializeGUI", myClassName, e, e.getLocalizedMessage(), false);
			driver.eop(myClassName, "initializeGUI", e);
		}
		
		return false;
	}
	
	public boolean initizliaeSocketInterface()
	{
		try
		{
				
			this.add(this.jpnlHEADING, BorderLayout.NORTH);			
			jpnlHEADING.add(BorderLayout.SOUTH, jpnl_jcbSortTableBy);
			
			jpnlNorthButtons.add(jbtnListen);
			jpnlNorthButtons.add(jbtnConnect);
			jpnlNorthButtons.add(jbtnDisconnectAll);
			jpnlNorthButtons.add(jlblNumConnectedSockets);
			jpnlNorthButtons.add(jcbEncryptionEnabled);
			jpnlNorthButtons.add(jcbEncryptionDisabled);
			jpnlNorthButtons.add(jlblEncryptionStatus);
			jpnlNorthButtons.add(jcbAgentResponseEnabled);
			this.jpnlConnectionInformation.add(BorderLayout.CENTER, jtfAddress);
			this.jpnlConnectionInformation.add(BorderLayout.EAST, jpnlNorthButtons);
			jpnlCONNECTION_CONTAINER.add(jpnlConnectionInformation);
			
			
			
				
			bg.add(this.jcbEncryptionDisabled);
			bg.add(this.jcbEncryptionEnabled);
			jpnlEncryption.add(BorderLayout.CENTER, jtfEncryption_key_AES);
			jpnlEncryption.add(BorderLayout.EAST, jpnlEncryptionButtons);
			//jpnlCONNECTION_CONTAINER.add(jpnlEncryption);
				
			this.jpnlHEADING.add(BorderLayout.NORTH, jpnlCONNECTION_CONTAINER);
			
			try	{	jpnlConnectionInformation.setBorder(new TitledBorder(UIManager.getBorder("TitledBorder.border"), "Connection Information", TitledBorder.LEADING, TitledBorder.TOP, null, new Color(0, 51, 255)));	}	catch(Exception e){}
			try	{	this.jpnlEncryption.setBorder(new TitledBorder(UIManager.getBorder("TitledBorder.border"), "Encryption", TitledBorder.LEADING, TitledBorder.TOP, null, new Color(0, 51, 255)));	}	catch(Exception e){}
			
			this.jbtnListen.addActionListener(this);
			this.jbtnConnect.addActionListener(this);
			this.jbtnDisconnectAll.addActionListener(this);
			this.jtfAddress.addActionListener(this);
			this.jcbEncryptionDisabled.addActionListener(this);
			this.jcbEncryptionEnabled.addActionListener(this);
			this.jcbAgentResponseEnabled.addActionListener(this);
			
			this.validate();
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "initializeGUI", e);
		}
		
		return false;
	}
	
	public boolean initializeJTable(Vector vctColNms, final Vector vctColToolTps)
	{
		try
		{
			dfltTblMdl = new DefaultTableModel(null, vctColNms);
			
			vctColNames = vctColNms;
			vctColToolTips = vctColToolTps;
			
			//
			//jpopup_SelectedRow
			//
			jpopup_SelectedRow = new JPopupMenu();
			
			jmnuitm_AddToFilter = new JMenuItem("Add to Filter");
			jmnuitm_DisplayInDataViewPane = new JMenuItem("Display in Data View Pane");
			jmnuitm_CopyToClipboard = new JMenuItem("Copy to Clipboard");
			jmnuitm_ClearFilter = new JMenuItem("Clear Filter");
			
			jpopup_SelectedRow.add(jmnuitm_AddToFilter);
			jpopup_SelectedRow.add(jmnuitm_DisplayInDataViewPane);
			jpopup_SelectedRow.add(jmnuitm_CopyToClipboard);
			jpopup_SelectedRow.add(jmnuitm_ClearFilter);
									
			
			jmnuitm_AddToFilter.addActionListener(this);
			jmnuitm_CopyToClipboard.addActionListener(this);
			jmnuitm_DisplayInDataViewPane.addActionListener(this);
			jmnuitm_ClearFilter.addActionListener(this);
			
			//
			//jpopup_EmptySpace_NoRowsSelected
			//
			jpopup_EmptySpace_NoRowsSelected = new JPopupMenu();
			
			jmnuitm_ClearFilter_NoRowSelected = new JMenuItem("Clear Filter");
			
			jpopup_EmptySpace_NoRowsSelected.add(this.jmnuitm_ClearFilter_NoRowSelected);
			
			jmnuitm_ClearFilter_NoRowSelected.addActionListener(this);
			
			
			jtblMyJTbl = new JTable(dfltTblMdl)//create subclass to make each cell non-editable and add specified tooltips when mouse hovers over cells
			{
				/**
				 * @override to disable being able to edit each cell
				 */
				public boolean isCellEditable(int r, int c)
				{
					return false;
				}
				
				/**
				 * Implement Table Header Tooltips
				 * 
				 */
				protected JTableHeader createDefaultTableHeader()
				{
					
					return new JTableHeader(columnModel)
					{
						public String getToolTipText(MouseEvent me)
						{
							try
							{
								String tip = null;
								java.awt.Point mouseHoverPoint = me.getPoint();
								int colIndex_HoverPoint = columnModel.getColumnIndexAtX(mouseHoverPoint.x);
								int colIndex = columnModel.getColumn(colIndex_HoverPoint).getModelIndex();
								
								if(colIndex < vctColToolTps.size())
									return (String) vctColToolTps.get(colIndex);
									
									else
										return "";																	
							}
							
							catch(Exception e)
							{
								return "";
							}
						}
					};
				}
				
				public Component prepareRenderer(TableCellRenderer renderer, int row, int col)
				{
					
					
						Component c = null;
						acceptComponent = false;
						TableCellRenderer cellRenderer;
						
						try
						{
							c = super.prepareRenderer(renderer,  row, col);
							
							if(row < dfltTblMdl.getRowCount())//finally, only proceed if the new row is less than or equal to the rows in the jtable	//2013-02-04 solo edits						
								acceptComponent = true;
						}
						catch(Exception e)
						{
//driver.eop("prepareRenderer", myClassName, e, e.getLocalizedMessage(), false);// 2013-02-05 solo edits
						}
						
						if(acceptComponent)
						{
							//Component c = super.prepareRenderer(renderer, row, col);
							cellRenderer = renderer;
							//ndeTemp_THREE = null;
							
							if(dfltTblMdl.getValueAt(row,  0) != null && dfltTblMdl.getValueAt(row,  0).equals("*") && !isCellSelected(row, col))
							{
								try
								{
								
								}
								catch(Exception e)
								{
//driver.eop("prepareRenderer", myClassName, e, e.getLocalizedMessage(), false);// 2013-02-05 solo edits
								}
							}
							
							else if(isCellSelected(row, col))
							{
								c.setForeground(Color.black);
							}
							
							else
							{
								c.setBackground(clrDefaultBackground);
								c.setForeground(clrDefaultForeground);
							}
							
							//Set Tooltip
							if(c instanceof JComponent && col < 0)
							{
								JComponent jc = (JComponent)c;
								jc.setToolTipText("Testing tool tip");
							}
							
							else if(c instanceof JComponent && col >= 0)
							{
								try
								{
									JComponent jc = (JComponent)c;
									jc.setToolTipText("" + dfltTblMdl.getValueAt(row, col));
								}catch(Exception e){}
							}
							
						}// end if(acceptComponent)
						
						else
						{
							//sop("Component rejected");
						}
						
						return c;
					}// end prepareRenderer
				
				
			};//end JTable SubClass
			
			//JTable Options
			this.jtblMyJTbl.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
			this.jtblMyJTbl.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
			this.jtblMyJTbl.setAutoCreateColumnsFromModel(false);
			this.jtblMyJTbl.setAutoCreateRowSorter(false);
			this.jtblMyJTbl.getTableHeader().setReorderingAllowed(false);//because the tooltips are setup by col, if the user changes the header, the tooltips are out of order; to prevent this, lock the headers from being able to move locations
			
			//Set Colors
			jtblMyJTbl.setOpaque(true);
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "initializeJTable", e);
		}
		
		return false;
	}
	
	public void valueChanged(ListSelectionEvent lse)
	{
		try
		{
			
			if(lse.getSource() == this.jtblMyJTbl.getSelectionModel())
			{
				//check if row is selected
				if(this.jtblMyJTbl.getSelectedRow() > -1)
				{
					//A row was selected
				}
			}
			
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "valueChanged", e);
		}		
		
	}
	
	public void actionPerformed(ActionEvent ae)
	{
		try
		{
			if(ae.getSource() == tmrUpdateJTable)
			{
				if(this.updateJTable)
				{
					this.updateJTable = false;
					//this entire ae section can be removed, however, to ensure thread safety, i'm implmenting a seperate update here
					
					
				}
			}
			
			
			else if(ae.getSource() == jbtnClearAndRefresh)
			{
				this.jtfFilter.setText("");
				StandardInListener.update_jtbl_Nodes(true);
			}
			
			else if(ae.getSource() == this.jbtnAddToFilter && this.dfltTblMdl.getRowCount() > 0)
			{
				filterOnSelectedRow(-1,-1);
			}
			
			else if(ae.getSource() == this.jbtnExportTable)
			{
				export_table_data("\t");
			}
			
			else if(ae.getSource() == jbtnDisplayInDataView  && this.dfltTblMdl.getRowCount() > 0)
			{
				displaySelectedRowInDataView(this.jtblMyJTbl.getSelectedRow());
			}
			
			else if(ae.getSource() == this.jtfFilter )
			{
				executeFilterAction(null, null);
			}
			
			else if(ae.getSource() == this.jtfMaxRowCount )
			{
				executeMaxRowCountAction();
			}
			
			else if(ae.getSource() == this.jmnuitm_AddToFilter)
			{
				filterOnSelectedRow(rowSelected, colSelected);
				//executeFilterAction();
			}
			
			else if(ae.getSource() == this.jmnuitm_ClearFilter)
			{
				clearAllFilters();
			}
			
			else if(ae.getSource() == this.jmnuitm_CopyToClipboard)
			{
				copyCellToClipboard(rowSelected, colSelected);
			}
			
			else if(ae.getSource() == this.jmnuitm_DisplayInDataViewPane)
			{
				displaySelectedRowInDataView(this.jtblMyJTbl.getSelectedRow());
			}
			
			else if(ae.getSource() == this.jmnuitm_ClearFilter_NoRowSelected)
			{
				clearAllFilters();
			}
			
			else if(ae.getSource() == this.jbtnConnect)
			{
				connect();
			}
			
			else if(ae.getSource() == this.jbtnListen)
			{
				//listen();
			}
			
			else if(ae.getSource() == jbtnDisconnectAgent)
			{
				//disconnect_agent();
			}
			
						
			else if(ae.getSource() == this.jtfAddress)
			{
				determine_connect_listen();
			}
			
						
			
			else if(ae.getSource() == jbtnDisconnectAll)
			{
				//disconnectAll();
			}
			
			else if(ae.getSource() == this.jcbEncryptionEnabled)
			{
				//set_encryption_key();
				Encryption.ENCRYPTION_ENABLED = true;
				this.jlblEncryptionStatus.setText("Encryption: [ENABLED] ");
			}
			
						
			else if(ae.getSource() == this.jtfEncryption_key_AES)
			{
				//set_encryption_key();
			}
			
			else if(ae.getSource() == this.jbtnSetEncryptionKey)
			{
				//set_encryption_key();
			}
			
			else if(ae.getSource() == this.jcbEncryptionDisabled)
			{
				myEncryption = null;
				Encryption.ENCRYPTION_ENABLED = false;
				this.jlblEncryptionStatus.setText("Encryption: [DISABLED]");
			}
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "ae", e);
		}
		
		this.validate();
	}
	
	public File export_table_data(String delimiter)
	{
		PrintWriter pwOut = null;
		File fleOut = null;
		
		try
		{
			if(this.jtblMyJTbl.getRowCount() < 1)
			{
				driver.jop_Error("No rows are populated to export!", true);
				return null;
			}
			
			File fle = driver.querySelectFile(false, "Please Export Location...", JFileChooser.FILES_AND_DIRECTORIES, false, false);
			
			if(fle == null)
			{
				return null;
			}						
			
			String path = fle.getCanonicalPath().trim();
			String file_name = "";
			
			if(fle.isDirectory())
			{
				if(!path.endsWith(File.separator))
					path = path + File.separator;
				
				file_name = path + "data_export_" + driver.get_time_stamp_hyphenated() + ".txt";
			}
			
			else//keep entire file name entered
			{
				file_name = fle.getCanonicalPath().trim();
			}						
			
			
			fleOut = new File(file_name);
			
			//Create new file
			
			
			try
			{
				pwOut = new PrintWriter(new FileWriter(fleOut, true));
			}
			catch(Exception e)
			{
				File f = new File("." + File.separator + Driver.NAME + File.separator + "export" + File.separator);
				
				try	{	f.mkdirs();	}catch(Exception ee){}
				
				file_name = f.getCanonicalPath().trim();
				
				if(!file_name.endsWith(File.separator))
					file_name = file_name + File.separator;
				
				fleOut = new File(file_name + File.separator + "data_export_" + driver.get_time_stamp_hyphenated() + ".txt");
				
				pwOut = new PrintWriter(new FileWriter(fleOut, true));
			}
			
			//init
			int cols_count = this.jtblMyJTbl.getColumnCount();
			String column_header = "";
			
			for(int i = 0; i < cols_count; i++)
			{
				column_header = column_header + this.dfltTblMdl.getColumnName(i) + delimiter;
			}
			
			//print header
			pwOut.println(column_header);
			
			//print each row
			try
			{
				String row = "";
				for(int i = 0; i < this.jtblMyJTbl.getRowCount(); i++)
				{
					row = "";
					for(int j = 0; j < cols_count; j++)
					{
						row = row + this.dfltTblMdl.getValueAt(i,  j) + delimiter;
					}
					
					//print row
					pwOut.println(row);
				}
			}
			catch(Exception e)
			{
				driver.jop_Error("Punt! It appears the Table changed while I was still writing its contents.\n\nI will stop exporting now...", true);
			}
			
						
			//driver.sound.play(ThreadSound.url_file_sent);
			driver.directive("If successful, output file has been written to \"" + fleOut.getCanonicalPath() + "\"");
			
			//attempt to open
			driver.open_file(fleOut);			
			
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "export_table_data", e);
		}
		
		try
		{
			pwOut.flush();
			pwOut.close();
		}catch(Exception e){}
		
		return fleOut;
	}
	
	/*public boolean disconnect_agent()
	{
		try
		{
			if(this.rowSelected < 0)
			{
				driver.jop("Punt! No agent currently selected!");
				return false;
			}
			
			ThreadSocketListener thd = getSelectedThread();
			
			if(thd == null)
				return false;
			
			if(driver.jop_Confirm("Confirm you wish to disconnect agent [" + thd.myAgentType + "] IP: [" + thd.mySourceAddress + "] Team Side: [" + thd.myTeam.TEAM_SIDE + "]", "Disconnect Agent") == JOptionPane.YES_OPTION)
			{
				thd.closeSocket();
			}
				
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "disconnect_agent");
		}
		
		return false;
	}*/
	
	/*public boolean sendCheckStatusCommand()
	{
		try
		{
			
			
			if(rowSelected < 0)
			{
				driver.jop_Error("Please select a row...", "No row selected...");
				return false;
			}
			
			Object id = this.dfltTblMdl.getValueAt(rowSelected, 0);
			
			if(id == null || id.toString().trim().equals(""))
			{
				driver.jop_Error("PUNT!!!\nPlease select a row...", "No row selected...");
				return false;
			}	
			
			//get the thread that matches the id
			ThreadSocketListener thd = ThreadSocketListener.getSocket(id);
			
			if(thd != null)
				thd.send_payload(0, "0");
			
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "sendCheckStatusCommand");
		}
		
		return false;
	}*/
	
	/*public ThreadSocketListener getSelectedThread()
	{
		try
		{
			Object id = this.dfltTblMdl.getValueAt(rowSelected, 0);
			
			if(id == null || id.toString().trim().equals(""))
			{
				driver.jop_Error("NOPE!!!\nPlease select a row...", "No row selected...");
				return null;
			}	
			
			//get the thread that matches the id
			return ThreadSocketListener.getSocket(id);
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "getSelectedThread");
		}
		
		return null;
	}*/
	
	/*public boolean set_encryption_key()
	{
		try
		{
			if(rowSelected < 0)
			{
				driver.jop_Error("Please select non-empty row!", "Unable to continue...");
				return false;
			}
			
			ThreadSocketListener thd = getSelectedThread();
			
			if(thd == null)
			{
				driver.jop("No valid socket was returned!");
				return false;
			}
			
			String key = driver.jop_Query("Please specify AES Encryption key", "Enter Key");
			
			thd.myEncryptionKey = key;
			thd.myEncryption = new Encryption(key, Encryption.default_iv_value);
			this.refreshSockets();
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName,  "set_encryption_key");
		}
		
		return false;
	}*/
	
	/*public boolean disconnectAll()
	{
		try
		{
			for(ThreadSocketListener thd : this.list_sockets)
			{
				try
				{
					thd.continue_run = false;
					thd.closeSocket();
				}
				catch(Exception e)
				{
					continue;
				}
			}
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName,  "disconnectAll");
		}
		
		return false;
	}*/
	
	public boolean connect()
	{
		try
		{
			//Try to split up the IP address and port
			
			String [] array = this.jtfAddress.getText().trim().split(":");
			
			if(array == null || array.length < 2)
				array = this.jtfAddress.getText().trim().split(" ");
			
			if(array == null || array.length < 2)
			{
				driver.sop("\nPUNT! Invalid IP Address / PORT specified! Unable to continue with expected action");
				return false;
			}
			
			String address = array[0].trim();
			int port = 9999;
			
			try	{	port = Integer.parseInt(array[1].trim());	}	
			catch(Exception e)
			{
				driver.sop("\nERROR! port appears to be invalid! Please try again");
				return false;
			}
									
			Socket skt = null;
			
			if(address.trim().equalsIgnoreCase("localhost") || address.trim().equalsIgnoreCase("local host"))
				address = "127.0.0.1";
			
			try
			{
				driver.sop("\nAttempting to establish outbound connection to " + address + " : " + port);
				skt = new Socket(address, port);
				
				//made it here, socket was successful!
				//ThreadSocketListener thd = new ThreadSocketListener(skt, null);
				
				//this.jtfAddress.setText("");
			}
			catch(Exception ee)
			{
				driver.sop("\nERROR! COULD NOT ESTABLISH CONNECTION TO "+ address + " : " + port);
			}
			
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.sop("\nPUNT!!! Invalid IP Address / PORT specified! Unable to continue with expected action");
		}
		
		return false;
	}
	
	/*public boolean listen()
	{
		try
		{
			int port = Integer.parseInt(this.jtfAddress.getText().trim());
			
			ServerSocketListener svr = new ServerSocketListener(port);
			
			//this.jtfAddress.setText("");
			
			return true;
		}
		catch(Exception e)
		{
			driver.sop("PUNT!!! Invalid input for the port.  Check this value and try again!");
		}
		
		return false;
	}*/
	
	public boolean determine_connect_listen()
	{
		try
		{
			if(this.jtfAddress.getText().trim().equals(""))
				return false;
			
			//check if the user wants to listen...
			
			try
			{
				int port = Integer.parseInt(this.jtfAddress.getText().trim());
				
				//made it here, it's a single port, listen!
				//return listen();
			}
			catch(Exception ee)
			{
				//failed just a number for the port, check if user wishes to connect out
				return connect();
			}
			
									
		}
		catch(Exception e)
		{
			driver.eop(myClassName,  "determine_connect_listen");
		}
		
		return false;
	}
	
public String hash_sha256(String strToHash) throws Exception {	return this.sha256Hash(strToHash);	}
	
	public String sha256Hash(String strToHash)
	{
		try
		{
			if(this.messageDigest == null)
				try	{	messageDigest = MessageDigest.getInstance("SHA-256");	}	catch(Exception e){driver.sop("ERROR!!!! CAN NOT SET SHA CRYPTO HASH!");}
			
			/*byte[] hash = messageDigest.digest("123".getBytes("UTF-8"));
			String code = Base64.encodeBase64String(hash);
			String code2 = this.hexBytesToString(hash);*/
			
			if(strToHash == null || strToHash.trim().equals(""))
				return "empty";
			
			return this.hexBytesToString(messageDigest.digest(strToHash.getBytes("UTF-8")));						
		}
		catch(Exception e)
		{
			driver.eop(myClassName,  "sha256Hash");
		}
		
		return "invalid2";
	}
	
	public String hexBytesToString(byte [] bytes)
	{
		try
		{
			//special thanks to http://stackoverflow.com/questions/5531455/how-to-hash-some-string-with-sha256-in-java
			
			StringBuffer buffer = new StringBuffer();
			
			for (int i = 0; i < bytes.length; i++) 
			{
	            String hex = Integer.toHexString(0xff & bytes[i]);
	            if(hex.length() == 1) buffer.append('0');
	            buffer.append(hex);
	        }
			
			return buffer.toString();
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "hexBytesToString");
		}
		
		return "invalid";
	}
	
	public boolean executeFilterAction(String filter_key, String filter_value)
	{
		try
		{			
			//update keys if necessary
			if(filter_key == null || filter_key.trim().equals(""))
			{
				//try to get what is currently selected 
				filter_key = ""+this.jcbSortTableBy.getSelectedItem();
				
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
				filter_value = this.jtfFilter.getText().trim();
				
				//ensure proper value
				if(filter_value == null || filter_value.trim().equals(""))
				{
					//just refresh
					StandardInListener.update_jtbl_Nodes(true);
					return false;
				}
			}
			
			//trim
			filter_value = filter_value.trim();
			
			//indicate gui should proceed
			this.jcbRejectUpdate.setSelected(false);
			
			//this will change based on the program, but we'll put the call here to actually put in the search below
			filter(filter_key, filter_value, SOURCE.TREE_SOURCE_NODES);
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "executeFilterAction", e);
		}
		
		return false;
	}
	
	
	public boolean filter(String Filter_Key, String Filter_Value, TreeMap<String, SOURCE> tree)
	{
		try
		{
			if(tree == null || tree.isEmpty())
				return false;
			
			if(Filter_Key == null || Filter_Key.trim().equals(""))
				return false;
			
			if(Filter_Value == null || Filter_Value.trim().equals(""))
				return false;
			
			if(jcbRejectUpdate.isSelected())
				return false;
									
			//ready to filter, remove all nodes previously			
			try	{	removeAllRows();	}	catch(Exception e){}
				
			//execute search on each node
			for(SOURCE node : tree.values())
			{
				if(node == null)
					continue;
					
				//get actual value from the node
				value_node = node.get(Filter_Key, Filter_Value);
				
				if(value_node != null && !value_node.trim().equals(""))
					addRow(node.get_jtable_row_summary("\t", false));
			}
			
			//sort
			sortJTable_ByRows(dfltTblMdl, jcbSortTableBy.getSelectedIndex(), sortInAscendingOrder);
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "filter", e);
		}
		
		return false;
	}
	
	public boolean executeMaxRowCountAction()
	{
		try
		{
			if(this.jtfMaxRowCount.getText().trim().equals(""))
			{
				maxRowCount = -1;
				return true;
			}
			
			maxRowCount = Integer.parseInt(this.jtfMaxRowCount.getText().trim());	
			
			if(maxRowCount < 0)
				jtfMaxRowCount.setText("");
			
			return true;
		}
		catch(Exception e)
		{
			//driver.eop(myClassName, "executeFilterAction", e);
			driver.jop_Error("NOPE! You must select a valid row number!", true);
			jtfMaxRowCount.setText("");
			maxRowCount = -1;
		}
		
		return false;
	}
	
	/**
	 * return the value of the selected row at column 0 i.e. SOURCE or ID value to search for a node from the jtable
	 */
	public String getSeletedRow_ID()
	{
		try
		{
			if(this.jtblMyJTbl.getSelectedRow() < 0)
				return null;
			
			//get first value (primary key)
			objValue = 	this.dfltTblMdl.getValueAt(this.jtblMyJTbl.getSelectedRow(), 0);
			
			if(objValue == null || objValue.toString().trim().equals(""))
				return null;	
			
			return ""+objValue;
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "getSelectedRow_ID", e);
		}
		
		return null;
	}
	
	public boolean displaySelectedRowInDataView(int rowSelected)
	{
		try
		{
			if(rowSelected < 0)
				return false;
			
			//get first value (primary key)
			objValue = 	this.dfltTblMdl.getValueAt(rowSelected, 0);
			
			if(objValue == null || objValue.toString().trim().equals(""))
				return false;	
			
			key = ""+objValue;
									
			//clear previous entries
			this.jta.clear();
			displayString = "";
			
			if(key == null)
			{
				driver.directive("No data found for key at selected row: " + rowSelected);
				return false;
			}
			
			key = key.trim();
			
			if(key.equals("") || key.equalsIgnoreCase("null"))
			{
				driver.directive("PUNT! No data found for key at selected row: " + rowSelected);
				return false;
			}
			
			if(process_double_click_for_resolution && StandardInListener.intrface != null)
				return StandardInListener.intrface.displaySelectedRowInDataView_resolution(key);
			if(process_double_click_for_application && StandardInListener.intrface != null)
				return StandardInListener.intrface.displaySelectedRowInDataView_application(key);
			if(process_double_click_for_cookies_host_system && StandardInListener.intrface != null)
				return StandardInListener.intrface.displaySelectedRowInDataView_cookies_host_system(rowSelected);
			if(process_double_click_for_network_map && StandardInListener.intrface != null)
				return StandardInListener.intrface.displaySelectedRowInDataView_network_map(rowSelected);
			if(process_double_click_for_update_oui_list && StandardInListener.intrface != null)
				return StandardInListener.intrface.displaySelectedRowInDataView_oui_in_use(rowSelected);
			/*if(process_double_click_for_cookies && StandardInListener.intrface != null)
				return StandardInListener.intrface.displaySelectedRowInDataView_cookie(key);*/
				
			
			//get specified data
			if(SOURCE.TREE_SOURCE_NODES.containsKey(key))
				displayString = SOURCE.TREE_SOURCE_NODES.get(key).getDataViewInformation("\n", true);
			else if(SOURCE.TREE_SOURCE_NODES.containsKey(key.toUpperCase()))
				displayString = SOURCE.TREE_SOURCE_NODES.get(key).getDataViewInformation("\n", true);
			else if(SOURCE.TREE_SOURCE_NODES.containsKey(key.toLowerCase()))
				displayString = SOURCE.TREE_SOURCE_NODES.get(key).getDataViewInformation("\n", true);
			
			//display selected data
			this.jta.append(displayString);
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "displaySelectedRowInDataView", e);
		}
		
		return false;
	}
	
	
	
	public Object getSelectedItemUnderColumn(String columnHeaderName)
	{
		try
		{
			selectedRow = this.jtblMyJTbl.getSelectedRow();
			
			if(selectedRow < 0)
				return null;
							
			try
			{
				selectedCol = this.jtblMyJTbl.getColumn(columnHeaderName).getModelIndex();
				
				if(selectedCol < 0)
					selectedCol = 0;
			}
			catch(Exception e)
			{
				selectedCol = 0;
			}
			
			selectedField = this.dfltTblMdl.getValueAt(selectedRow, selectedCol);
			
			if(selectedField == null)
				return null;
			
			
			
			return objValue;
			
			//driver.sop(objValue.toString().trim() + " Selected item: " + node_mac.MAC);
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "getSelectedItem", e);
		}
		
		return null;
	}
//	public boolean updateBeaconImplants()
//	{
//		try
//		{
//			
//			//else remove everything and add the agents back in
//			try
//			{
//				removeAllRows();							
//				
//			}catch(Exception e){}//do n/t
//			
//			try
//			{
//				
//				jbtnRefresh.setEnabled(false);
//				jbtnDisconnectImplant.setEnabled(false);
//				jbtnGoogleMap.setEnabled(false);
//				
//			}catch(Exception e){}
//			
//		
//			/*if(alBeaconTerminals.size() > 0)
//			{
//				try
//				{
//					jtblBeaconImplants.jbtnRefresh.setEnabled(true);
//					jtblBeaconImplants.jbtnDisconnectImplant.setEnabled(true);
//					jtblBeaconImplants.jbtnGoogleMap.setEnabled(true);
//				}catch(Exception e){}
//				
//			}*/
//			
//			Thread_Terminal thread = null;						
//			
//			for(int i = 0; i < Driver.alBeaconTerminals.size(); i++)
//			{
//				try
//				{
//					thread = Driver.alBeaconTerminals.get(i);
//					
//					//
//					//JTABLE CONNECTED IMPLANTS
//					//
//					this.addRow(thread.getJTableRowData()); //<-- this is just a series of add Strings for each column
//										
//					
//				}
//				catch(ArrayIndexOutOfBoundsException aiob)
//				{
//					driver.sop("***No BEACON thread to add!!!");
//				}
//				
//			}
//			
//			
//			
//			return true;
//		}
//		catch(Exception e)
//		{
//			driver.eop(myClassName, "updateBeaconImplants", e);
//		}
//		
//		return false;
//	}

	public void itemStateChanged(ItemEvent ie)
	{
		try
		{
			if(ie.getSource() == this.jcbSortTableBy)
			{
				if(this.dfltTblMdl.getRowCount() > 1)
				{
					sortJTable_ByRows(this.dfltTblMdl, this.jcbSortTableBy.getSelectedIndex(), this.sortInAscendingOrder);
				}
			}
			
			else if(ie.getSource() == this.jcbSortInAscendingOrder)
			{
				//toggle the sort flag
				this.sortInAscendingOrder = !this.sortInAscendingOrder;
				
				if(this.dfltTblMdl.getRowCount() > 1)
				{
					sortJTable_ByRows(this.dfltTblMdl, this.jcbSortTableBy.getSelectedIndex(), this.sortInAscendingOrder);
				}
			}
			
			else if(ie.getSource() == this.jcbAddToFilter && this.dfltTblMdl.getRowCount() > 0)
			{
				filterOnSelectedRow(rowSelected, colSelected);
			}
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "ie", e);
		}
		
		this.validate();
	}
	
	public boolean filterOnSelectedRow(int rowPreselected, int colPreSelected)
	{
		try
		{
			selectedRow = -1;
			selectedCol = 0;
			
			try	
			{	 
				if(rowPreselected >= 0)
					selectedRow = rowPreselected;
				else
					selectedRow = this.jtblMyJTbl.getSelectedRow();
				
				if(colPreSelected >= 0)
					selectedCol = colPreSelected;
				else			
					selectedCol = this.jtblMyJTbl.getSelectedColumn();					
				
				selectedField = this.dfltTblMdl.getValueAt(selectedRow, selectedCol);
						
				this.FILTER_KEY = null;
				this.FILTER_VALUE = ""+selectedField;
				
				if(FILTER_VALUE == null || FILTER_VALUE.trim().equalsIgnoreCase("null"))
				{
					FILTER_VALUE = null;
					driver.jop_Error("No valid filter value specified!", true);
				}
				
				if(selectedRow > -1 && selectedCol > -1 && selectedField != null && !selectedField.toString().trim().equals(""))
				{
					//execute filter specification action
					this.jcbSortTableBy.setSelectedIndex(selectedCol);
					
					//GET FILTER KEY
					FILTER_KEY = ""+this.jcbSortTableBy.getSelectedItem();
					
					if(FILTER_KEY == null || FILTER_KEY.trim().equalsIgnoreCase("null"))
						FILTER_KEY = null;
					
					//this.jtfFilter.setText(""+selectedField);
															
					//add this filter to all remaining filter streams for others
					for(int i = 0; list_JTables != null && i < list_JTables.size(); i++)
					{												
						//see if we can set the jcombobox as well
						//check the column in the jtbl that the user has specified to Sort on based on the extracted text from the jcombobox of filter options
						filter_col_index = list_JTables.get(i).dfltTblMdl.findColumn(this.jcbSortTableBy.getSelectedItem().toString().trim());
						
						if(filter_col_index > -1)
						{
							//set the text in the filter
							list_JTables.get(i).jtfFilter.setText("*"+selectedField + "*");
							
							//set the jcb for the other filters
							list_JTables.get(i).jcbSortTableBy.setSelectedIndex(filter_col_index);
						}
					}
															
				}
				
				//driver.sop("Selected item: " + selectedField);
				
			}	catch(Exception e)	{selectedRow = -1; selectedCol = -1;}
			
			
			//filter
			executeFilterAction(FILTER_KEY, FILTER_VALUE);
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "filterOnSelectedRow", e);
		}
		
		return false;
	}
	
	
	public boolean clearAllFilters()
	{		
		try
		{
			for(int i = 0; list_JTables != null && i < list_JTables.size(); i++)
			{
				//set the text in the filter
				list_JTables.get(i).resetFilter();
			}
			
			StandardInListener.update_jtbl_Nodes(true);
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "clearFilter", e);
		}
		
		return false;
	}
	
	public boolean copyCellToClipboard(int rowPreselected, int colPreSelected)
	{
		try
		{
			selectedRow = -1;
			selectedCol = 0;
			
			if(rowPreselected >= 0)
				selectedRow = rowPreselected;
			else
				selectedRow = this.jtblMyJTbl.getSelectedRow();
			
			if(colPreSelected >= 0)
				selectedCol = colPreSelected;
			else			
				selectedCol = this.jtblMyJTbl.getSelectedColumn();					
			
			selectedField = this.dfltTblMdl.getValueAt(selectedRow, selectedCol);
			
			if(selectedField == null)
				selectedField = "";
			
		driver.copyToClipboard(""+selectedField);
		
		return true;
				 
				
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "copyCellToClipboard", e);
		}
		
		return false;
	}
	
	
	
	public boolean resetFilter()
	{		
		try
		{
			this.jtfFilter.setText("");
			//executeFilterAction(null, null);
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "clearFilter", e);
		}
		
		return false;
	}
	
	public boolean addRow(Vector<String> vctInfoToPopulate)
	{
		try
		{
			//ensure vector passed in has proper number of elements as the column header for this class's jtable
			/*if(vctInfoToPopulate == null || vctInfoToPopulate.size() != this.vctColNames.size()))
			 * 	throw new Exception("Vector passed in does not contain proper number of elements");*/
			 
			if(this.jcbRejectUpdate != null && this.jcbRejectUpdate.isSelected())
				return false;
			
			if(vctInfoToPopulate == null) //2013-02-04 solo edits
				return false;
			
			//else, add the row!
			this.dfltTblMdl.addRow(vctInfoToPopulate.toArray());
			
			
			//check if we need to highlight the row
			this.dfltTblMdl.fireTableDataChanged();
			
			
			this.jlblNumRows.setText("" + this.dfltTblMdl.getRowCount());
			
			this.validate();
			this.jtblMyJTbl.validate();
			
			//this.updateJTable = true;
			
			return true;
		}
		
		catch(ArrayIndexOutOfBoundsException aiobe)
		{
			//dismiss this error for now!
			//2013-02-04 solo edits
		}
		
		catch(Exception e)
		{
			driver.eop(myClassName, "addRow", e);
		}
		
		return false;
	}
	
	/*public boolean refreshSockets()
	{
		try
		{
			
			this.removeAllRows();
			
			if(!this.list_sockets.isEmpty())
			{
				for(ThreadSocketListener sockets : list_sockets)
				{
					try
					{
						this.addRow(sockets.getJTableRow());
					}
					catch(Exception e)
					{
						continue;
					}
				}
			}
			
			this.jlblNumRows.setText("" + this.jtblMyJTbl.getRowCount());
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "refreshSockets");
		}
		
		return false;
		
	}*/

	public boolean removeAllRows()
	{
		try
		{
			if(this.jcbRejectUpdate != null && this.jcbRejectUpdate.isSelected())
				return false;
			
			/*if(this.jcbRejectUpdate.isSelected())
				return true;*/
			
			this.dfltTblMdl.getDataVector().removeAllElements();
			
			//unfortunately at this point, if the above doesn't work, we'll have to use a while model.getRowCont() > 0 model.deleteRow(0); to clear the rows
								
			this.dfltTblMdl.fireTableDataChanged();
			this.jtblMyJTbl.validate();
			
			this.jlblNumRows.setText("0");
			
			//update the max row count here
			try
			{
				if(this.jtfMaxRowCount.getText() != null && !this.jtfMaxRowCount.getText().trim().equals(""))
				{
					this.maxRowCount = Integer.parseInt(this.jtfMaxRowCount.getText().trim());
					
					if(maxRowCount < 0)
					{
						maxRowCount = -1;
						this.jtfMaxRowCount.setText("");
					}
				}
				else 
					maxRowCount = -1;
					
			}
			catch(Exception e)
			{
				maxRowCount = -1;
				this.jtfMaxRowCount.setText("");
			}
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "removeAllRows", e);
		}
		
		return false;
	}
	
	public boolean addRow(String [] row)
	{
		try
		{
			if(this.jcbRejectUpdate != null && this.jcbRejectUpdate.isSelected())
				return false;

			
			if(row == null || row.length < 1) 
				return false;
			
			//check if we're reached row count
			if(maxRowCount > -1 && dfltTblMdl.getRowCount() >= maxRowCount)
				return true;
			
			this.dfltTblMdl.addRow(row);
			
			this.jlblNumRows.setText(""+dfltTblMdl.getRowCount());
			
			/*//determine if we are filtering
			filter = this.jtfFilter.getText().toLowerCase().trim();
			
			if(filter.trim().equals("") )
			{
				//no filter, add and move on!
				this.dfltTblMdl.addRow(row);
				return true;
			}
			
			//otherwise, check if the row contains the data from the specified filter
			
			//check the column in the jtbl that the user has specified to Sort on based on the extracted text from the jcombobox of filter options
			filter_col_index = this.dfltTblMdl.findColumn(this.jcbSortTableBy.getSelectedItem().toString().trim());
			
			if(filter_col_index < 0)//something went wrong, just add the row and do not filter
				this.dfltTblMdl.addRow(row);
			
			//otherwise check if the rows match, if so, include
			else if(row[filter_col_index] != null && row[filter_col_index].trim().equalsIgnoreCase(filter))
				this.dfltTblMdl.addRow(row);

			//check * <filter> * 
			else if(row[filter_col_index] != null && filter.startsWith("*") && filter.endsWith("*"))
			{
				filter = filter.replaceAll("\\*", "");
				
				if(row[filter_col_index].toLowerCase().trim().contains(filter))		
					this.dfltTblMdl.addRow(row);
			}
			
			//check *<filter>
			else if(row[filter_col_index] != null && filter.startsWith("*"))
			{
				filter = filter.replaceAll("\\*", "");
				
				if(row[filter_col_index].toLowerCase().trim().endsWith(filter))		
					this.dfltTblMdl.addRow(row);
			}
			
			//check <filter>*
			else if(row[filter_col_index] != null && filter.endsWith("*"))
			{
				filter = filter.replaceAll("\\*", "");
				
				if(row[filter_col_index].toLowerCase().trim().startsWith(filter))		
					this.dfltTblMdl.addRow(row);
			}
			
			//check everything
//			else if(row[filter_col_index] != null && row[filter_col_index].toLowerCase().trim().contains(filter))
//			{				
//				this.dfltTblMdl.addRow(row);
//			}
			
			//check if we need to highlight the row
			//good code below, however to save processing time, i'm moving to the call for the sort function
//			this.dfltTblMdl.fireTableDataChanged();			
//			this.jlblNumRows.setText("" + this.dfltTblMdl.getRowCount());
//			
//			this.validate();
//			this.jtblMyJTbl.validate();
			
			*/
			
			return true;
		}
		
		catch(ArrayIndexOutOfBoundsException aiobe)
		{
			//dismiss this error for now!
			//2013-02-04 solo edits
		}
		
		catch(Exception e)
		{
			driver.eop(myClassName, "addRow", e);
		}
		
		return false;
	}
	
	

	public boolean removeRow(int rowToRemove)
	{
		try
		{
			if(this.jcbRejectUpdate != null && this.jcbRejectUpdate.isSelected())
				return false;
			
			this.dfltTblMdl.removeRow(rowToRemove);
			
			this.jtblMyJTbl.revalidate();
			this.dfltTblMdl.fireTableRowsDeleted(rowToRemove, rowToRemove);//first row, last row
			this.dfltTblMdl.fireTableRowsUpdated(0,  this.dfltTblMdl.getRowCount()-1);
			
			this.dfltTblMdl.fireTableDataChanged();
			
			this.jlblNumRows.setText("" + this.dfltTblMdl.getRowCount());
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "removeRow", e);
		}
		
		return false;	
	}
	
	public boolean addRow(String override_primary_column_header, String [] row)
	{
		try
		{
			if(this.jcbRejectUpdate != null && this.jcbRejectUpdate.isSelected())
				return false;

			
			if(row == null || row.length < 1) 
				return false;
			
			//check if we're reached row count
			if(maxRowCount > -1 && dfltTblMdl.getRowCount() >= maxRowCount)
				return true;
			
			if(override_primary_column_header != null && !override_primary_column_header.trim().equals(""))
				row[0] = override_primary_column_header.trim();
			
			this.dfltTblMdl.addRow(row);
			
			/*//determine if we are filtering
			filter = this.jtfFilter.getText().toLowerCase().trim();
			
			if(filter.trim().equals("") )
			{
				//no filter, add and move on!
				this.dfltTblMdl.addRow(row);
				return true;
			}
			
			//otherwise, check if the row contains the data from the specified filter
			
			//check the column in the jtbl that the user has specified to Sort on based on the extracted text from the jcombobox of filter options
			filter_col_index = this.dfltTblMdl.findColumn(this.jcbSortTableBy.getSelectedItem().toString().trim());
			
			if(filter_col_index < 0)//something went wrong, just add the row and do not filter
				this.dfltTblMdl.addRow(row);
			
			//otherwise check if the rows match, if so, include
			else if(row[filter_col_index] != null && row[filter_col_index].trim().equalsIgnoreCase(filter))
				this.dfltTblMdl.addRow(row);

			//check * <filter> * 
			else if(row[filter_col_index] != null && filter.startsWith("*") && filter.endsWith("*"))
			{
				filter = filter.replaceAll("\\*", "");
				
				if(row[filter_col_index].toLowerCase().trim().contains(filter))		
					this.dfltTblMdl.addRow(row);
			}
			
			//check *<filter>
			else if(row[filter_col_index] != null && filter.startsWith("*"))
			{
				filter = filter.replaceAll("\\*", "");
				
				if(row[filter_col_index].toLowerCase().trim().endsWith(filter))		
					this.dfltTblMdl.addRow(row);
			}
			
			//check <filter>*
			else if(row[filter_col_index] != null && filter.endsWith("*"))
			{
				filter = filter.replaceAll("\\*", "");
				
				if(row[filter_col_index].toLowerCase().trim().startsWith(filter))		
					this.dfltTblMdl.addRow(row);
			}
			
			//check everything
//			else if(row[filter_col_index] != null && row[filter_col_index].toLowerCase().trim().contains(filter))
//			{				
//				this.dfltTblMdl.addRow(row);
//			}
			
			//check if we need to highlight the row
			//good code below, however to save processing time, i'm moving to the call for the sort function
//			this.dfltTblMdl.fireTableDataChanged();			
//			this.jlblNumRows.setText("" + this.dfltTblMdl.getRowCount());
//			
//			this.validate();
//			this.jtblMyJTbl.validate();
			
			*/
			
			return true;
		}
		
		catch(ArrayIndexOutOfBoundsException aiobe)
		{
			//dismiss this error for now!
			//2013-02-04 solo edits
		}
		
		catch(Exception e)
		{
			driver.eop(myClassName, "addRow", e);
		}
		
		return false;
	}
	
	public String getSelectedCellContents()
	{
		try
		{
			return (String)this.jtblMyJTbl.getValueAt(this.getSelectedRowIndex(), this.getSelectedColIndex());
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "getSelectedCellContents", e);
		}
		
		return "UNKNOWN";
	}
	
	public String getCellContents(int row, int col)
	{
		try
		{
			return (String)this.jtblMyJTbl.getValueAt(row, col);
		}
		
		catch(Exception e)
		{
			driver.eop(myClassName, "getCellContents", e);
		}
		
		return "UNKNOWN";
	}
	
	public int getSelectedRowIndex()
	{
		try
		{
			return this.jtblMyJTbl.getSelectedRow();
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "getSelectedRowIndex", e);
		}
		
		return 0;
	}
	
	public int getSelectedColIndex()
	{
		try
		{
			return this.jtblMyJTbl.getSelectedColumn();			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "getSelectedColIndex", e);
		}
		
		return 0;
	}
	
	public boolean sortJTable()
	{
		try
		{
			sortJTable_ByRows(this.dfltTblMdl, this.jcbSortTableBy.getSelectedIndex(), this.sortInAscendingOrder);			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "sortJTable", e);
		}
		
		return false;
	}
	
	public boolean sortJTable_ByRows(DefaultTableModel dfltTModel, int colToSort, boolean ascending)
	{
		try
		{
			if(this.dfltTblMdl.getRowCount() < 1)
			{
				return false;
			}
			
			//get data from the table
			vctTblData = dfltTModel.getDataVector();
			
			if(vctTblData == null || vctTblData.size() < 2)
			{
				return false;
			}
			
			//Sort the model
			Collections.sort(vctTblData, new ColumnSorter(colToSort, ascending));
			this.dfltTblMdl.fireTableStructureChanged();
			
						
			this.jlblNumRows.setText("" + this.dfltTblMdl.getRowCount());
			
			this.validate();
			this.jtblMyJTbl.validate();
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "sortJTable_ByRows - Model", e);
		}
		
		return false;
	}
	
	/**
	 * This comparator class is used to sort vectors of data
	 * this class was taken from http://www.exampledepot.com/egs/javax.swing.table/sorter.html?1=rel and http://www.exampledepot.com/egs/javax.swing.table/SortCol.html
	 * 
	 */
	public class ColumnSorter implements Comparator
	{
		int colIndex = 0;
		boolean ascending = true;
		
		/**
		 * Constructor to take the colindex to sort and boolean if sorting in ascending order
		 */
		ColumnSorter(int colIndex, boolean ascending)
		{
			//ensure colIndex is > 0
			if(colIndex < 0)
				colIndex = 0;
			
			this.colIndex = colIndex;
			this.ascending = ascending;
		}
		
		public int compare(Object a, Object b)
		{			
			v1 = (Vector) a;
			v2 = (Vector) b;
			o1 = v1.get(colIndex);
			o2 = v2.get(colIndex);
			
			try
			{
				double val1 = Double.parseDouble(o1.toString().trim());
				double val2 = Double.parseDouble(o2.toString().trim());
				
				if(!jcbSortInAscendingOrder.isSelected())
					return (int)(val2 - val1);
				
				return (int)(val1 - val2);
			}
			catch(Exception e)
			{
				//do n/t and fall through for additional comparissons
			}						
			
			//treat empty strains like nulls
			if(o1 instanceof String && ((String)o1).length() == 0)
			{
				o1 = null;
			}
			
			if(o2 instanceof String && ((String)o2).length() == 0)
			{
				o2 = null;
			}
									
			//sort nulls so they appear last, regardless of sort order
			if(o1 == null && o2 == null)
			{
				return 0;
			}
			
			else if(o1 == null)
			{
				return 1;
			}
			
			else if(o2 == null)
			{
				return -1;
			}
			
			//convert both to same case
			o1 = o1.toString().toLowerCase();
			o2 = o2.toString().toLowerCase();
			
			if(o1 instanceof Comparable)
			{
				if(ascending)
				{
					return ((Comparable)o1).compareTo(o2);
				}
				
				else
				{
					return ((Comparable)o2).compareTo(o1);
				}
			}
			
			else
			{				
				if(ascending)
				{
					return o1.toString().compareTo(o2.toString());
				}
				
				else
				{
					return o2.toString().compareTo(o1.toString());
				}
			}//end else
			
		}//end compare mtd
		
	}//end class ColumnSorter

	@Override
	public void mouseClicked(MouseEvent me) 
	{
		try
		{
			if(me.getClickCount() == 2)
			{
				//double click
				if(me.getSource() == this.jtblMyJTbl)
				{
					displaySelectedRowInDataView(this.jtblMyJTbl.getSelectedRow());
				}
				
				else if(me.getSource() == this.header_jtable)
				{
					//get selected col header index
					filter_col_index = this.jtblMyJTbl.columnAtPoint(me.getPoint());
					
					//set jcbsort
					this.jcbSortTableBy.setSelectedIndex(filter_col_index);
					
					//driver.sop("Column clicked: " + filter_col_index +  " col name: " + this.jtblMyJTbl.getColumnName(filter_col_index));
					
					//toggle the sort order
					this.jcbSortInAscendingOrder.setSelected(!this.jcbSortInAscendingOrder.isSelected());
					
					//sort!
					sortJTable_ByRows(this.filter_col_index);
					
				}
								
			}
			
			else if(me.getSource() == jscrlpneJTable)
			{
				//this.jpopup_EmptySpace_NoRowsSelected.show(me.getComponent(), me.getX(), me.getY());
				
				//if(me.isPopupTrigger() && me.getComponent() instanceof JScrollPane)
				if(SwingUtilities.isRightMouseButton(me))
				{
					this.jpopup_EmptySpace_NoRowsSelected.show(me.getComponent(), me.getX(), me.getY());				
				}
			}
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "mouseClicked", e);
		}
		
		this.validate();
	}
	
	public boolean sortJTable_ByRows(int col_index)
	{
		try
		{
			if(col_index > -1)
				return sortJTable_ByRows(this.dfltTblMdl, col_index, this.sortInAscendingOrder);
			
			//return true;
		}
		
		catch(Exception e)
		{
			driver.eop(myClassName, "sortJTable_ByRows - Col", e);
		}
		
		return false;
	}

	@Override
	public void mouseEntered(MouseEvent me) 
	{
		try
		{
			
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "mouseEntered", e);
		}
		
		this.validate();
	}

	@Override
	public void mouseExited(MouseEvent me)
	{
			try
			{
				
				
			}
			catch(Exception e)
			{
				driver.eop(myClassName, "mouseExited", e);
			}
			
			this.validate();
		}

	@Override
	public void mousePressed(MouseEvent me) 
	{
		try
		{
			
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "mousePressed", e);
		}
		
		this.validate();
	}

	@Override
	public void mouseReleased(MouseEvent me) 
	{
		try
		{
			if(me.getSource() == this.jtblMyJTbl)
			{
				rowSelected = this.jtblMyJTbl.rowAtPoint(me.getPoint());
				colSelected = this.jtblMyJTbl.columnAtPoint(me.getPoint());
				
				if(rowSelected >= 0 && rowSelected < this.jtblMyJTbl.getRowCount())
				{
					//selected the row
					this.jtblMyJTbl.setRowSelectionInterval(rowSelected, rowSelected);
					
					if(me.isPopupTrigger() && me.getComponent() instanceof JTable)
					{
						this.jpopup_SelectedRow.show(me.getComponent(), me.getX(), me.getY());				
					}
				}
				
				
			}
			
			
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "mouseReleased", e);
		}
		
		this.validate();
	}

	public boolean updateConnectedSocketCount()
	{
		try
		{
			//this.jlblNumConnectedSockets.setText("" + this.list_sockets.size());
			this.validate();
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "updateConnectedSocketCount");
		}
		
		return false;
	}
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
}//end JTable Class!



























