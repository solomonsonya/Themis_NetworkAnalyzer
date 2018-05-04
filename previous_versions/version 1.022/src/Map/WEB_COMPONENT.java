
package Map;

import java.net.URI;
import java.net.URL;

import javafx.application.Application;
import javafx.embed.swing.JFXPanel;
import javafx.event.ActionEvent;
import javafx.event.EventHandler;
import javafx.scene.Group;
import javafx.scene.Scene;
import javafx.scene.control.Hyperlink;
import javafx.scene.layout.VBox;
import javafx.scene.web.WebEngine;
import javafx.scene.web.WebView;
import javafx.stage.Stage;
import java.awt.*;
import java.awt.event.*;
import java.io.File;

import javax.swing.*;
import javafx.*;
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



public class WEB_COMPONENT extends JPanel
{
	WebView browser = null;
    WebEngine webEngine = null;
    
    public volatile Scene scene = null;
	public final JFXPanel fxPanel = new JFXPanel();

	String myComponentToLoadPath = "";
	
	public WEB_COMPONENT(String pathToLoad) throws Exception 
	{
		myComponentToLoadPath = pathToLoad;
				
		SwingUtilities.invokeLater(new Runnable() 
		{
			@Override
			public void run() 
			{
				try {
					initAndShowGUI();
				} catch (Exception e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}	
				
				
					
			}
		});
		
		this.setLayout(new BorderLayout());;
		this.add(BorderLayout.CENTER, fxPanel);

	}
	
	private void initAndShowGUI() throws Exception 
	{		

		Platform.runLater(new Runnable() {
			@Override
			public void run() {
				try {
					initFX(fxPanel);
				} catch (Exception e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				
				
			}
		});
		
	}
	
	
	private void initFX(JFXPanel fxPanel) throws Exception 
	{				
		
		// This method is invoked on the JavaFX thread
		
		browser = new WebView();
	    webEngine = browser.getEngine();
		
		scene  = new Scene(browser, 1000,600);
		
		//URL url = getClass().getResource(myComponentToLoadPath);
		File fle = new File(myComponentToLoadPath);
		URL url = fle.toURL();
		webEngine.load(url.toExternalForm());
		
		webEngine.setJavaScriptEnabled(true);	
		
		fxPanel.setScene(scene);
	}

	
	
}
