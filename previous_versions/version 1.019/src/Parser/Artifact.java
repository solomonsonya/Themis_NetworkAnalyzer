/**
 * A http_referer, dns_query_name, http_full_uri is an artifact.  The actual values within these request are what we'll use to create unique profiles for each node (IP address)
 * communicating across our network.  The entries will be the SOURCE nodes that have made a request for each artifact
 * 
 * @author Solomon Sonya
 */

package Parser;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.util.LinkedList;
import java.util.TreeMap;
import Driver.*;
import Driver.Log;
import Driver.StandardInListener;
import Driver.Start;
import Encryption.Encryption;
import Profile.Resolution;
import Profile.SOURCE;
import ResolutionRequest.ResolutionRequest_ThdSocket;

public class Artifact 
{
	public static final String myClassName = "Artifact";
	public static Driver driver = new Driver();
		
	//
	//PROFILES
	//
	public static volatile TreeMap<String, Artifact> tree_artifact_protocol = new TreeMap<String, Artifact>();
	public static volatile TreeMap<String, Artifact> tree_artifact_dst_mac = new TreeMap<String, Artifact>();
	public static volatile TreeMap<String, Artifact> tree_artifact_dst_ip = new TreeMap<String, Artifact>();
	
	/**www.excite.com and excite.com/123.exe will all come out to be excite.com*/
	public static volatile TreeMap<String, Artifact> tree_artifact_domain_name_request_trimmed = new TreeMap<String, Artifact>();
	public static volatile TreeMap<String, Artifact> tree_artifact_http_referer = new TreeMap<String, Artifact>();
	public static volatile TreeMap<String, Artifact> tree_artifact_cookie = new TreeMap<String, Artifact>();
	public static volatile TreeMap<String, Artifact> tree_artifact_http_host_virtual = new TreeMap<String, Artifact>();
	public static volatile TreeMap<String, Artifact> tree_artifact_user_agent = new TreeMap<String, Artifact>();
	
	/*public static volatile TreeMap<String, Artifact> tree_artifact_ = new TreeMap<String, Artifact>();
	public static volatile TreeMap<String, Artifact> tree_artifact_ = new TreeMap<String, Artifact>();
	public static volatile TreeMap<String, Artifact> tree_artifact_ = new TreeMap<String, Artifact>();
	public static volatile TreeMap<String, Artifact> tree_artifact_ = new TreeMap<String, Artifact>();
	public static volatile TreeMap<String, Artifact> tree_artifact_ = new TreeMap<String, Artifact>();
	public static volatile TreeMap<String, Artifact> tree_artifact_ = new TreeMap<String, Artifact>();
	public static volatile TreeMap<String, Artifact> tree_artifact_ = new TreeMap<String, Artifact>();
	public static volatile TreeMap<String, Artifact> tree_artifact_ = new TreeMap<String, Artifact>();
	public static volatile TreeMap<String, Artifact> tree_artifact_ = new TreeMap<String, Artifact>();*/
	
	
	public volatile TreeMap<String, Artifact> myArtifactRootTree = null;
	
	/**e.g. excite.com, orbits, google*/
	public String KEY = "";
	
	/**e.g. http_referer*/
	public String TYPE = "";
	
				
	public volatile TreeMap<String, SOURCE> tree_source = new TreeMap<String, SOURCE>();
		
	
	public Artifact(String key, String type, SOURCE source, TreeMap<String, Artifact> root)
	{
		try
		{
			KEY = key;
			TYPE = type;
			myArtifactRootTree = root;
			
			if(!root.containsKey(key))
			{
				root.put(key,  this);
				//tree_source.put(source.src_ip, source);
				link_node(source);
			}
			else
			{
				//retrieve the existing pointer
				root.get(key).link_node(source);
			}			
			
			
			//link self to root
			
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "Constructor - 1", e);
		}
		
	}
	
	public boolean link_node(SOURCE source)
	{
		try
		{
			if(!this.tree_source.containsKey(source.src_ip))
			{
				//
				//LINK
				//
				tree_source.put(source.src_ip, source);
				
				//
				//WRITE PROFILE
				//
				
			}
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "link_node", e);
		}
		
		return false;
	}

}
