/**
 * @author Solomon Sonya
 */

package ResolutionRequest;

import java.io.*;
import java.util.*;
import Encryption.*;
import Driver.Driver;
import Driver.Start;

import java.net.*;

public class ResolutionRequest_ThdSocket extends Thread implements Runnable
{
	public static final String myClassName = "ResolutionRequest_ThdSocket";
	public volatile Driver driver = new Driver();

	public ResolutionRequest_ServerSocket parent = null;
	public Socket mySocket = null;
			
	public volatile BufferedReader brIn = null;
	public volatile PrintWriter pwOut = null;
	
	public volatile String CONNECTION_ADDRESS = "";
	public volatile int distant_end_port = 7779;
	public volatile String distant_end_ip = "";
	
	public volatile boolean continue_run = true;
	
	public static volatile LinkedList<ResolutionRequest_ThdSocket> list_outbound_connections = new LinkedList<ResolutionRequest_ThdSocket>();
	
	/**iterate through this list to send all collected sensor data across*/
	public static volatile LinkedList<ResolutionRequest_ThdSocket> ALL_CONNECTIONS = new LinkedList<ResolutionRequest_ThdSocket>();
	
	public volatile static int parser_index = 0;
	
	public volatile Encryption ENCRYPTION = null;
	public volatile String encryption_line = "";
	
	public ResolutionRequest_ThdSocket(ResolutionRequest_ServerSocket par, Socket skt)
	{
		try
		{
			parent = par;
			mySocket = skt;
			
			if(Start.encryption_key != null && !Start.encryption_key.trim().equalsIgnoreCase("null") && !Start.encryption_key.trim().equals(""))
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
	
	public ResolutionRequest_ThdSocket(String address)
	{
		try
		{
			if(address == null || address.trim().equals(""))
			{
				driver.jop_Error("ERROR! It appears you are missing address parameters for the connect command! Please try again!", "Invalid Address");
				driver.sop("ERROR! It appears you are missing address parameters for the connect command! Please try again!");
			}
			
			else
			{
				address = address.trim();				
				
				String array [] = null;
				
				if(address.contains(":"))
					array = address.split(":");
				else if(address.contains(","))
					array = address.split(",");
				else 
					array = address.split(" ");
				
				String addr = array[0].trim();
				int port = Integer.parseInt(array[1].trim());
				
				if(addr.equalsIgnoreCase("localhost") || addr.equalsIgnoreCase("local host") || addr.equalsIgnoreCase("-localhost") || addr.equalsIgnoreCase("-local host"))
					addr = "127.0.0.1";
				
				//Connect
				driver.directive("Attempting to connect sensor out to transport data to PARSER --> " + addr + " : " + port);
				
				try
				{
					Socket skt = new Socket(addr, port);
					
					ResolutionRequest_ThdSocket thd = new ResolutionRequest_ThdSocket(null, skt);
				}
				catch(Exception ee)
				{
					driver.jop_Error("ERROR! I was unable to establish a connection to PARSER at --> " + addr + " : " + port, "Unable to Connect...");
					driver.directive("ERROR! I was unable to establish a connection to PARSER at --> " + addr + " : " + port);
				}
			}
			
			
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "Constructor - 2", e);
		}
		
	}
	
	public ResolutionRequest_ThdSocket(String addr, String PORT)
	{
		try
		{
			if(addr == null || addr.trim().equals("") || PORT == null || PORT.trim().equals(""))
			{
				driver.jop_Error("ERROR!!! It appears you are missing address parameters for the connect command! Please try again!", "Invalid Address");
				driver.sop("ERROR!!! It appears you are missing address parameters for the connect command! Please try again!");
			}
			
			else
			{
				addr = addr.trim();
				PORT = PORT.trim();				
								
				int port = Integer.parseInt(PORT.trim());
				
				if(addr.equalsIgnoreCase("localhost") || addr.equalsIgnoreCase("local host") || addr.equalsIgnoreCase("-localhost") || addr.equalsIgnoreCase("-local host"))
					addr = "127.0.0.1";
				
				//Connect
				driver.directive("Attempting to connect sensor out to transport data to PARSER --> " + addr + " : " + port);
				
				try
				{
					Socket skt = new Socket(addr, port);
					
					ResolutionRequest_ThdSocket thd = new ResolutionRequest_ThdSocket(null, skt);
				}
				catch(Exception ee)
				{
					driver.jop_Error("ERROR!!! I was unable to establish a connection to PARSER at --> " + addr + " : " + port, "Unable to Connect...");
					driver.directive("ERROR!!! I was unable to establish a connection to PARSER at --> " + addr + " : " + port);
				}
				
			}
			
			
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "Constructor - 3", e);
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
			
			if(parent != null)//received connection from serversocket
				sop("New socket connection received from " + mySocket.getRemoteSocketAddress() + " across interface " + parent.myBoundInterface + ". Total number of connected hosts: " + parent.list_connections.size());
			else//established outbound connection from StandardIn
				sop("SUCCESS! New socket connection established to " + mySocket.getRemoteSocketAddress());
				
			//CONNECTION_ADDRESS = ""+mySocket.getRemoteSocketAddress();
			this.set_connection_address();
			
			ALL_CONNECTIONS.add(this);
			
			this.send("Successfully connected to " + driver.FULL_NAME + " [REQUEST RESOLUTION] by Solomon Sonya @Carpenter 1010");
			
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
			try		{			sop(""); sop("Parser Socket Closed for thread: " + this.getId() + " [" + CONNECTION_ADDRESS + "].  Total number of connected hosts: " + parent.list_connections.size());	}	catch(Exception e){}
			
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
						
			
			driver.directive(myClassName + " - ready to process resolution for line -->" + encryption_line);
			
			return true;
		}
		
		catch(Exception e)
		{
			driver.eop(myClassName, "sop", e);
		}
		
		return false;
	}
	
	public static boolean set_encryption(String key)
	{
		try
		{
			if(key == null || key.trim().equals("") || key.trim().equalsIgnoreCase("null"))
			{
				System.out.println("ENCRYPTION HAS BEEN DISABLED!");
				Start.encryption_key = null;
			}
			else
			{
				key = key.trim();
				
				Start.encryption_key = key;
				
				System.out.println("Encryption key has been set to [" + key + "]");
			}
			
			
			
			//update threads
			for(ResolutionRequest_ThdSocket skt : ResolutionRequest_ThdSocket.ALL_CONNECTIONS)
			{
				try
				{
					if(Start.encryption_key == null)
						skt.ENCRYPTION = null;
					else
						skt.ENCRYPTION = new Encryption(key, Encryption.default_iv_value);
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
			System.out.println("Exception handled in " + myClassName + " set_encryption mtd -->" + e.getLocalizedMessage());
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
