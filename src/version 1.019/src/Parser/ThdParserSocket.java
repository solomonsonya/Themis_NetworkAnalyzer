/**
 * @author Solomon Sonya
 */

package Parser;

import java.awt.Color;
import java.io.*;
import java.util.*;
import Encryption.*;
import Driver.*;
import Driver.Start;

import java.net.*;

public class ThdParserSocket extends Thread implements Runnable
{
	public static final String myClassName = "ThdParserSocket";
	public volatile Driver driver = new Driver();

	public ParserServerSocket parent = null;
	public Socket mySocket = null;
			
	public volatile BufferedReader brIn = null;
	public volatile PrintWriter pwOut = null;
	
	public volatile String CONNECTION_ADDRESS = "";
	public volatile int distant_end_port = 9998;
	public volatile String distant_end_ip = "";
	
	public volatile boolean continue_run = true;
	
	public static volatile LinkedList<ThdParserSocket> list_outbound_connections = new LinkedList<ThdParserSocket>();
	
	/**iterate through this list to send all collected sensor data across*/
	public static volatile LinkedList<ThdParserSocket> ALL_CONNECTIONS = new LinkedList<ThdParserSocket>();
	
	public volatile static int parser_index = 0;
	
	public volatile Encryption ENCRYPTION = null;
	public volatile String encryption_line = "";
	
	public ThdParserSocket(ParserServerSocket par, Socket skt)
	{
		try
		{
			parent = par;
			mySocket = skt;
			
			if(Start.encryption_key != null && !Start.encryption_key.trim().equalsIgnoreCase("null"))
			{
				//set the new key!
				ENCRYPTION = new Encryption(Start.encryption_key, Encryption.default_iv_value);
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
			brIn = new BufferedReader(new InputStreamReader(mySocket.getInputStream()));
			pwOut = new PrintWriter(new OutputStreamWriter(mySocket.getOutputStream()), true);
			
			if(parent != null && parent.list_connections != null)
			{
				parent.list_connections.addLast(this);
			}
			else
			{
				list_outbound_connections.add(this);
			}
			
			if(StandardInListener.intrface != null)
			{
				StandardInListener.intrface.jlblNOT_CONNECTED.setText("CONNECTED");
				StandardInListener.intrface.jlblNOT_CONNECTED.setForeground(Color.white);
				StandardInListener.intrface.jlblNOT_CONNECTED.setBackground(Color.green.darker().darker());
				
				
			}
			
			
			if(parent != null)//received connection from serversocket
				sop("New socket connection received from " + mySocket.getRemoteSocketAddress() + " across interface " + parent.myBoundInterface + ". Total number of connected hosts: " + parent.list_connections.size());
			else//established outbound connection from StandardIn
				sop("SUCCESS!!!! New socket connection established to " + mySocket.getRemoteSocketAddress());
				
			//CONNECTION_ADDRESS = ""+mySocket.getRemoteSocketAddress();
			this.set_connection_address();
			
			ALL_CONNECTIONS.add(this);
			
			this.send("Successfully connected to " + driver.FULL_NAME + " [PARSER] by Solomon Sonya @Carpenter 1010");
			
			String line = "";
			
			while((line = brIn.readLine()) != null)
			{
				if(line.trim().equals(""))
					continue;
				
				determine_command(line);
				
				if(!continue_run)
					break;
			}
			
			
			//driver.directive("[PARSER] --> Commencing termination actions with " + CONNECTION_ADDRESS);
			
		}
		
		catch(SocketException se)
		{
			if(se.getLocalizedMessage() != null && se.getLocalizedMessage().equalsIgnoreCase("Connection reset"))
			{
				sop("PUNT! Distant end closed socket to me!");
			}
			
			else
			{
				driver.eop(myClassName, "run mtd", se);
			}
			
		}
		
		catch(Exception e)
		{
			/*driver.eop(myClassName, "run", e);
			e.printStackTrace(System.out);*/
			
			driver.sop("\n\n * * * SOCKET CLOSED\n\n ");
		}
						
		//driver.directive("Parser socket closed to " + CONNECTION_ADDRESS);
		
		/*try		{			parent.list_connections.remove(this);}	catch(Exception e){}						
		try		{			this.brIn.close();} catch(Exception e){}
		try		{			this.pwOut.close();} catch(Exception e){}
		try		{			this.mySocket.close();} catch(Exception e){}		
		try		{			this.list_outbound_connections.remove(this);}	catch(Exception e){}
		try		{			this.ALL_CONNECTIONS.remove(this);}	catch(Exception e){}
		try		{			sop("\nSocket Closed for thread: " + this.getId() + " [" + CONNECTION_ADDRESS + "].  Total number of connected hosts: " + parent.list_connections.size());	}	catch(Exception e){}
		
		
		System.gc();*/
		
		close_socket();
		
	}
	
	public boolean set_connection_address()
	{
		try
		{
			CONNECTION_ADDRESS = ""+mySocket.getRemoteSocketAddress();
			
			if(parent != null)
				distant_end_port = parent.PORT;
			else
				distant_end_port = this.mySocket.getLocalPort();
			
			try	{				distant_end_ip = CONNECTION_ADDRESS.substring(0, CONNECTION_ADDRESS.lastIndexOf(":")).trim();			}
			catch(Exception e){distant_end_ip = CONNECTION_ADDRESS;}
			
			if(distant_end_ip.startsWith("/"))
				distant_end_ip = distant_end_ip.substring(1).trim();
			if(distant_end_ip.startsWith("\\"))
				distant_end_ip = distant_end_ip.substring(1).trim();
									
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "set_connection_address", e);
		}
		
		return false;
	}
	
	public boolean close_socket()
	{
		try
		{
			try		{			if(parent != null) parent.list_connections.remove(this);}	catch(Exception e){}						
			try		{			this.brIn.close();} catch(Exception e){}
			try		{			this.pwOut.close();} catch(Exception e){}
			try		{			this.mySocket.close();} catch(Exception e){}		
			try		{			this.list_outbound_connections.remove(this);}	catch(Exception e){}
			try		{			this.ALL_CONNECTIONS.remove(this);}	catch(Exception e){}
			
			try
			{
				if(ALL_CONNECTIONS == null || ALL_CONNECTIONS.isEmpty() || list_outbound_connections == null || list_outbound_connections.isEmpty())
				{
					if(StandardInListener.intrface != null)
					{
						StandardInListener.intrface.jlblNOT_CONNECTED.setText("NOT CONNECTED");
						StandardInListener.intrface.jlblNOT_CONNECTED.setForeground(Color.yellow);
						StandardInListener.intrface.jlblNOT_CONNECTED.setBackground(Color.red);
					}
				}
				
			}
			catch(Exception e)
			{}
			
			
			try		{			sop(""); sop("Parser Socket Closed for thread: " + this.getId() + " [" + CONNECTION_ADDRESS + "].  Total number of connected hosts: " +ALL_CONNECTIONS.size());	}	catch(Exception e){}
			
			
			
			System.gc();
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "close_socket", e);
		}
		
		return false;
	}
	
	
	public boolean determine_command(String line)
	{
		try
		{
			if(line == null || line.trim().equals(""))
				return false;
			
			//assume encryption
			encryption_line = line;
			
			if(ENCRYPTION != null)
				encryption_line = ENCRYPTION.decrypt(line);
			
			if(Parser.list_parsers != null && Parser.list_parsers.size() > 0)
			{
				Parser.list_parsers.get(parser_index++).parse(encryption_line);
				
				if(parser_index % Parser.list_parsers.size() == 0)
					parser_index = 0;
			}
			
			return true;
		}
		
		catch(Exception e)
		{
			driver.eop(myClassName, "determine_command", e);
		}
		
		return false;
	}
	
	public boolean sop(String out)
	{
		try
		{
			driver.sop("[SocketListener " + this.getId() + "] --> " + out);
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "sop", e);
		}
		
		return false;
	}
	
	
	
	
	public boolean send(String out)
	{
		try
		{
			if(pwOut == null)
				return this.close_socket();			
			
			pwOut.println(out);
			pwOut.flush();
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "send", e);
		}
		
		return false;
	}
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
}
