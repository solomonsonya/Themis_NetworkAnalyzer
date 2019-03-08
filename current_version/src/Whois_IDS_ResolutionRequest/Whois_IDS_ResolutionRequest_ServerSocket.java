/**
 * Thread created only to RECEIVE Sensory Information across the Sockets
 * 
 * Received information is put here for whois retrieval. Once found, it will be broadcasted back to the connected agents.  
 * 
 * Any information received across these sockets will be processed.
 * 
 * @author Solomon Sonya
 */

package Whois_IDS_ResolutionRequest;

import java.io.*;
import java.util.*;

import Driver.Driver;
import Driver.Log;

import java.net.*;

public class Whois_IDS_ResolutionRequest_ServerSocket extends Thread implements Runnable
{
	public static final String myClassName = "Whois_IDS_ResolutionRequest_ServerSocket";
	public volatile static Driver driver = new Driver();

	public static volatile LinkedList<Whois_IDS_ResolutionRequest_ServerSocket> list_server_sockets = new LinkedList<Whois_IDS_ResolutionRequest_ServerSocket>();
	
	public static final int DEFAULT_PORT = 7779;
	
	public volatile int PORT = DEFAULT_PORT;
	
	public volatile ServerSocket svrskt = null;
	
	public static volatile boolean continue_run = true;
	
	public volatile String myBoundInterface = "";
	
	public volatile LinkedList<Whois_IDS_ResolutionRequest_ThdSocket> list_connections = new LinkedList<Whois_IDS_ResolutionRequest_ThdSocket>();
	
	
	
	public Whois_IDS_ResolutionRequest_ServerSocket(int preferred_port)
	{
		try
		{
			PORT = preferred_port;
				
						
			
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
			driver.directive("Attempting to establish whois request resolution server socket on port [" + PORT + "]");
			
			try
			{
				svrskt = new ServerSocket(PORT);
			}
			catch(Exception e)
			{
				driver.sop("ERROR! I WAS UNABLE TO BIND REQUEST RESOLUTION SERVER SOCKET TO PORT: " + PORT + ".  It is appears this port is already bound by a separate process!  I am attempting to bind to a free port...");
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
				
				Whois_IDS_ResolutionRequest_ThdSocket thd = new Whois_IDS_ResolutionRequest_ThdSocket(this, skt);
			}
			
			driver.directive("\nPUNT PUNT! REQUEST RESOLUTION ServerSocket is closed for " + myBoundInterface);
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
		
		return "Request Resolution ServerSocket - " + PORT;
	}
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
}
