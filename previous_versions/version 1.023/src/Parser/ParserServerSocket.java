/**
 * Thread created only to RECEIVE Sensory Information across the Sockets
 * 
 * Received information is put onto the parsers for processing. 
 * 
 * Any information received across these sockets will be processed.
 * 
 * @author Solomon Sonya
 */

package Parser;

import java.io.*;
import java.util.*;

import Driver.Driver;
import Driver.Log;

import java.net.*;

public class ParserServerSocket extends Thread implements Runnable
{
	public static final String myClassName = "ParserServerSocket";
	public volatile static Driver driver = new Driver();

	public static volatile LinkedList<ParserServerSocket> list_server_sockets = new LinkedList<ParserServerSocket>();
	
	public static final int DEFAULT_SENSOR_PORT = 9998;
	public static final int DEFAULT_PARSER_PORT = 9997;
	
	public static final int DEFAULT_PORT = DEFAULT_PARSER_PORT;
	
	public volatile int PORT = DEFAULT_PORT;
	
	public volatile ServerSocket svrskt = null;
	
	public static volatile boolean continue_run = true;
	
	public volatile String myBoundInterface = "";
	
	public volatile LinkedList<ThdParserSocket> list_connections = new LinkedList<ThdParserSocket>();
	
	public static final int NUM_PARSER_THREADS = 40;
	//public static volatile LinkedList<Parser> list_PARSER_threads = new LinkedList<Parser>();
	
	public ParserServerSocket(int preferred_port)
	{
		try
		{
			PORT = preferred_port;
						
			//start parser threads
			for(int i = 0; i < NUM_PARSER_THREADS && Parser.list_parsers.size() < NUM_PARSER_THREADS; i++)
			{
				Parser.list_parsers.add(new Parser());
			}
			
			
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
			//start serversocket
			driver.directive("Attempting to establish parser server socket on port [" + PORT + "]");
			
			try
			{
				svrskt = new ServerSocket(PORT);
			}
			catch(Exception e)
			{
				driver.sop("ERROR! I WAS UNABLE TO BIND PARSER SERVER SOCKET TO PORT: " + PORT + ".  It is appears this port is already bound by a separate process!  I am attempting to bind to a free port...");
				svrskt = new ServerSocket(0);
				PORT = svrskt.getLocalPort();
			}
			
			myBoundInterface = svrskt.getInetAddress().getHostAddress() + ":" + PORT;
			
			driver.directive("SUCCESS! " + myClassName + " is bound to " + svrskt.getInetAddress().getHostAddress() + ":" + PORT + ".  Ready for new connections across port " + PORT);
			
			//add self to list
			list_server_sockets.add(this);
			
			//
			//LISTEN FOR NEW CONNECTIONS
			//
			while(continue_run)
			{
				Socket skt = svrskt.accept();
				
				ThdParserSocket thd = new ThdParserSocket(this, skt);
			}
			
			driver.directive("\nPUNT PUNT! PARSER ServerSocket is closed for " + myBoundInterface);
		}
		catch(Exception e)
		{
			
		}
	}
	
	
	public String get_status()
	{
		try
		{
			try
			{	return "" + svrskt.getInetAddress().getHostAddress() + ":" + PORT + " \tNum Connections: [" + this.list_connections.size() + "]";	}
			catch(Exception ee)
			{	return myBoundInterface;	}
					
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "get_status", e);			
		}
		
		return "PARSER ServerSocket - " + PORT;
	}
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
}
