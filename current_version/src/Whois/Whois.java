package Whois;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.util.ConcurrentModificationException;
import java.util.LinkedList;
import java.util.TreeMap;
import Parser.*;
import javax.swing.Timer;
import Profile.*;
import java.io.*;
import java.net.*;
import Node.*;

import Driver.*;
import java.awt.event.*;

public class Whois 
{
	public static final String myClassName = "Whois";
	public static volatile Driver driver = new Driver();
	public static volatile String version_whois = "1.001";
	
	/**to reduce network traffic, we can choose not to send back "no response received from X query*/
	public volatile boolean SURPRESS_WHOIS_RETRIEVAL_FAILURE_RESPONSE = false;
	
	public static volatile boolean verbose = true;
	
	public static final String no_results_returned_from_selected_query = "no results returned from selected query";
	public static final String ioc_found = "* * * ALERT * * * malicious entry found on IOC\t ";
	
	public static final int ioc_alert_text_length = ioc_found.toLowerCase().trim().length();
	
	/**Stores the value detected by the IDS, e.g. maliciousweb.com, 216.54.1.5, etc... - This will be searched later to update our understanding of malicious requests*/
	public static final TreeMap<String, Whois_Tuple> tree_ioc_value = new TreeMap<String, Whois_Tuple>();
	
	public volatile boolean is_on_ioc = false;
	public volatile LinkedList<String> list_ioc_detection_listing = null;
	public volatile String ioc_listing_details = "";
	
	public volatile Process process = null;		
	public volatile ProcessBuilder process_builder = null;
	public volatile BufferedReader brIn = null;
	public volatile BufferedReader brError = null;
	public volatile BufferedWriter buffered_writer = null;	
	
	/**Time Stamp for the last time input was received - we'll use this to deflect a new interrupt if we're still processing an input line - updated in stream gobblers*/
	public static volatile long last_process_time_stamp = 0;
	
	public volatile String listing;
	public volatile boolean logged_i_am_on_ioc_list = false;
	public static volatile File fleIOC_Alert_Whois = null;
	public static volatile PrintWriter pwOut_IOC_Alert_Whois = null;
	
	 
	
	//public static volatile Log log_ioc_alert_whois = new Log("ioc_alert_whois",  "ioc_alert_whois", 250, 999999999);
	
	//
	//Logging
	//
	public static File fleTopFolder_Log = null;
	public static String pathTopFolder_Log = null;
	
	public static File fleTopFolder_whois = null;
	public static String pathTopFolder_whois = null;
	
	public static File fleTopFolder_whois_excalibur = null;
	public static String pathTopFolder_whois_excalibur = null;
	
	public static File fleTopFolder_whois_registrars = null;
	public static String pathTopFolder_whois_registrars = null;
	
	public static File fleTopFolder_tld_registrars = null;
	public static String pathTopFolder_tld_registrars = null;
	
	public File fleLog_Whois = null;
	
	public static volatile File fleLog_Whois_Excalibur = null;
	public static volatile PrintWriter pwOut_Excalibur_Whois_Data_File = null;
	
	public File fleLog_Whois_MASTER_Excalibur = null;
	public File fleLog_TLD_Registrar = null;
	public File fleLog_Whois_Registrars = null;
	
	
	public static final int max_whois_derivation_threads = 50;
	BufferedReader brWhoisImport = null;
	Timer tmrWhoisImport = null;
	public volatile LinkedList<Whois> list_whois_derivation_agents = null;
	/**To indicate which whois to remove after we iterate through the list*/
	public volatile LinkedList<Whois> list_whois_to_remove = null;
	public volatile boolean process_interrupt_whois_derivation = true;
	
	public volatile static LinkedList<Whois> list_ioc_whois = new LinkedList<Whois>();
	
	
	/////////////////////////////////
	///////////////////
	///////////
	///////
	//

	public static final String delimiter1 = "#####";
	public static volatile boolean drop_subdomains = false; 
	
	/**e.g. drop google.com/123/586/xyz.zip to only let us focus on the domain since we're trying to find the owners of the domains vice the actual resourse being hosted at the owned domain*/
	public static volatile boolean drop_resource_url_from_domain = true; 
	public volatile static LinkedList<Whois> list_search = null;
	public static boolean begins_with = false, ends_with = false, contains = false, equals = false;

	public static volatile boolean STORE_WHOIS = true;
	public static volatile boolean debug = true;
	public volatile Node_GeoIP node_geo = null;
	public volatile Node_Nslookup node_nslookup = null;

	public volatile boolean is_parse_whois_complete = false;

	public static final String [] arr_dismiss_words = new String[]
			{
					"notice", 
					"terms of use", 
					"the data is for", 
					"this data", 
					"this information", 
					"copyright", 
					"url of the icann whois data problem", 
					"only for lawful purposes and that", 
					"visit", 
					"for more information", 
					"by the following ", 
					"http", 
					"url of the icann whois", 
					"allow, enable, or otherwise support", 
					"whois lookup made", 
					"whois lookup", 
					"this information and the", 
					"this whois", 
					"by the terms of", 
					"which includes", 
					"you may not", 
					"reuse", 
					"access may", 
					"you agree",
					"in russian",
					"in english",
					"submitting",
					"query",
					"whois",
					"register",
					"limit",
					"available",
					"invalid",
					"disclose",
					"is provided",
					"information purposes",
					"not guarantee",
					"only",
					"otherwise",
					"allow",
					"enable",
					"reserves the",
					"submitting",
					"--",
					"for complete",
					"please note",
					"registration service p",
					"onsite(s)",
					"for additional",
					"no nameServers",
					"note:",
					"supporto tecnico",
					"no match",
					"keys:",
					"flags:",
					"conditions:",
					"the query",
			};

	public static volatile boolean STOP = false;

	public volatile String value = "", value_graph = null, value_links = null, value_search = null;;

	public static final int SOCKET_TIMEOUT = 15*1000;

	public static final int PING_COUNT = 2;

	/**Contains IOC values. For now, this will just be the raw values of any indicator to raise an alert*/
	//public static volatile TreeMap<String, Whois_Tuple> tree_ioc_values = new TreeMap<String, Whois_Tuple>();
	
	/**Contains whois server for COM, NET, ORG, etc*/
	public static volatile TreeMap<String, Whois> cache_IANA_TLD = new TreeMap<String, Whois>();

	/**keep a list of domains we have looked up already to not perform the same lookup several times*/
	public static volatile TreeMap<String, String> tree_not_found_cache = new TreeMap<String, String>();
	
	/**Contains whois registrar servers for google.com eg. whois.markmonitor.com*/
	public static volatile TreeMap<String, Whois> tree_whois_registrar_server = new TreeMap<String, Whois>();

	/**Contains whois record for google.com, yahoo.com, bing.com, etc*/
	public static volatile TreeMap<String, Whois> tree_whois_lookup = new TreeMap<String, Whois>();
	
	/**Contains artifacts for each whois. e.g. the IP addresses associated to a single domain (nslookup), etc s.t. we could be more successful when plugged into Themis since themis mainly provides us with IP addresses from the network*/
	//public static volatile TreeMap<String, Whois_Tuple> tree_whois_artifacts = new TreeMap<String, Whois_Tuple>();

	/**cache to not perform the same lookup multiple times*/
	public static volatile TreeMap<String, String> tree_cache_request_lookup = new TreeMap<String, String>();
	
	/**set when we wish to process subdomains as well*/
	public boolean override_and_process_full_subdomain = false;

	public volatile String [] arr = null;
	public volatile String value_1 = null;
	public volatile String value_2 = null;
	public volatile String value_3 = null;

	public volatile boolean surpress_output = false;

	public volatile int EXECUTION_ACTION = 0;
	public String LOOKUP = null;

	public static final String WHOIS_IANA_ORG = "whois.iana.org";
	public static final int PORT_WHOIS = 43;
	public volatile String LOOKUP_ORIGINAL = "";

	public volatile String ping_command = "";

	/**google.com*/
	public volatile String DOMAIN_NAME = null;

	/**e.g. COM from google.com*/
	public volatile String TLD = null;

	/**e.g. whois:        whois.verisign-grs.com*/
	public volatile String TLD_WHOIS_REGISTRAR_FULL_LINE = null;

	/**e.g. whois.verisign-grs.com*/
	public volatile String TLD_WHOIS_REGISTRAR = null;

	/**e.g. whois.markmonitor.com*/
	public volatile String REGISTRAR_WHOIS_SERVER = null;
	
	/**e.g. 1.co.uk should keep the full lookup and not only process the subdomain*/
	public boolean keep_ensure_lookup_and_do_not_remove_subdomains = false;

	/**Activate when storing domains e.g. 1.co.uk*/
	public boolean store_mode_DOMAIN_NAME = false;
	/**Activate when storing domains e.g. 1.co.uk*/
	public boolean store_mode_REGISTRANT = false;
	/**Activate when storing domains e.g. 1.co.uk*/
	public boolean store_mode_REGISTRANT_TYPE = false;
	/**Activate when storing domains e.g. 1.co.uk*/
	public boolean store_mode_REGISTRANT_ADDRESS = false;
	/**Activate when storing domains e.g. 1.co.uk*/
	public boolean store_mode_DATA_VALIDATION = false;
	/**Activate when storing domains e.g. 1.co.uk*/
	public boolean store_mode_REGISTRAR = false;
	/**Activate when storing domains e.g. 1.co.uk*/
	public boolean store_mode_RELEVANT_DATES = false;
	/**Activate when storing domains e.g. 1.co.uk*/
	public boolean store_mode_REGISTRATION_STATUS = false;
	/**Activate when storing domains e.g. 1.co.uk*/
	public boolean store_mode_NAME_SERVERS = false;

	/**Activate when storing domains e.g. abc.eu*/
	public boolean store_mode_TECHNICAL = false;

	/**Activate when storing domains e.g. abc.eu*/
	public boolean store_mode_ADMINISTRATOR = false;

	public static volatile Log log_tld_all = null;
	public static volatile Log log_tld_registrar_not_found = null;
	public static volatile Log log_excalibur_whois_data_line = null; 
	public static volatile Log log_domain_name_not_found = null;

	/**DUPLICATE EXISTS! all caps is what we searched and normalized for. lowercase is what we paresed directly from server*/
	
	public volatile String registry_domain_id = null;
	/**DUPLICATE EXISTS! all caps is what we searched and normalized for. lowercase is what we paresed directly from server*/
	public volatile String registrar_whois_server = null;
	public volatile String registrar_url = null;
	public volatile String registrant_url = null;
	public volatile String admin_url = null;
	public volatile String tech_url = null;
	public volatile String billing_url = null;
	public volatile String updated_date = null;
	public volatile String creation_date = null;
	/**.uk*/
	public volatile String registration_status = null;
	public volatile String registrar_registration_expiration_date = null;
	public volatile String reseller = null;
	public volatile String registrar = null;
	public volatile String registrar_iana_id = null;
	public volatile String registrar_abuse_contact_email = null;
	public volatile String registrar_abuse_contact_email_domain_name = null;
	public volatile String registrar_abuse_contact_phone = null;
	public volatile String registrar_abuse_contact_ext = null;
	public volatile String description = null;
	public volatile String domain_status1 = null;
	public volatile String domain_status2 = null;
	public volatile String domain_status3 = null;
	public volatile String domain_status4 = null;
	public volatile String domain_status5 = null;
	public volatile String domain_status6 = null;
	public volatile String domain_status7 = null;
	public volatile String domain_status8 = null;
	public volatile String domain_status9 = null;
	public volatile String domain_status10 = null;
	public volatile String name_server_NAME1 = null;
	public volatile String name_server_NAME2 = null;
	public volatile String name_server_NAME3 = null;
	public volatile String name_server_NAME4 = null;
	public volatile String name_server_NAME5 = null;
	public volatile String name_server_NAME6 = null;
	public volatile String name_server_NAME7 = null;
	public volatile String name_server_NAME8 = null;
	public volatile String name_server_NAME9 = null;
	public volatile String name_server_NAME10 = null;
	public volatile String name_server_NAME11 = null;
	public volatile String name_server_NAME12 = null;
	public volatile String name_server_NAME13 = null;
	public volatile String name_server_NAME14 = null;
	public volatile String name_server_NAME15 = null;
	public volatile String name_server_NAME16 = null;
	public volatile String name_server_NAME17 = null;
	public volatile String name_server_NAME18 = null;
	public volatile String name_server_NAME19 = null;
	public volatile String name_server_NAME20 = null;
	public volatile String name_server_IP1 = null;
	public volatile String name_server_IP2 = null;
	public volatile String name_server_IP3 = null;
	public volatile String name_server_IP4 = null;
	public volatile String name_server_IP5 = null;
	public volatile String name_server_IP6 = null;
	public volatile String name_server_IP7 = null;
	public volatile String name_server_IP8 = null;
	public volatile String name_server_IP9 = null;
	public volatile String name_server_IP10 = null;
	public volatile String name_server_IP11 = null;
	public volatile String name_server_IP12 = null;
	public volatile String name_server_IP13 = null;
	public volatile String name_server_IP14 = null;
	public volatile String name_server_IP15 = null;
	public volatile String name_server_IP16 = null;
	public volatile String name_server_IP17 = null;
	public volatile String name_server_IP18 = null;
	public volatile String name_server_IP19 = null;
	public volatile String name_server_IP20 = null;
	public volatile String dnssec = null;
	public volatile String reason = null;

	public volatile LinkedList<String> list_name_server_ip = new LinkedList<String>();
	public volatile LinkedList<String> list_name_server_names = new LinkedList<String>();

	public volatile String  whois_server = null;
	public volatile String  referral_url = null;
	public volatile String  registry_registrant_id = null;
	public volatile String  registrant_name = "";
	/**.uk*/
	public volatile String  data_validation = null;
	/**.uk*/
	public volatile String  registrant_type = "";
	public volatile String  registrant_organization = null;
	public volatile String  registrant_street = null;
	public volatile String  registrant_city = null;
	public volatile String  registrant_state_province = null;
	public volatile String  registrant_postal_code = null;
	public volatile String  registrant_country = null;
	public volatile String  registrant_phone = null;
	public volatile String  registrant_phone_ext = "";
	public volatile String  registrant_fax = "";
	public volatile String  registrant_fax_ext = "";
	public volatile String  registrant_email = "";
	public volatile String  registrant_email_domain_name = "";
	public volatile String  registry_admin_id = null;
	public volatile String  admin_name = null;
	public volatile String  admin_organization = null;
	public volatile String  admin_street = null;
	public volatile String  admin_city = null;
	public volatile String  admin_state_province = null;
	public volatile String  admin_postal_code = null;
	public volatile String  admin_country = null;
	public volatile String  admin_phone = "";
	public volatile String  admin_phone_ext = "";
	public volatile String  admin_fax = "";
	public volatile String  admin_fax_ext = "";
	public volatile String  admin_email = null;
	public volatile String  admin_email_domain_name = null;
	public volatile String  registry_tech_id = null;
	public volatile String  tech_name = null;
	public volatile String  tech_organization = null;
	public volatile String  tech_street = null;
	public volatile String  tech_city = null;
	public volatile String  tech_state_province = null;
	public volatile String  tech_postal_code = null;
	public volatile String  tech_country = null;
	public volatile String  tech_phone = "";
	public volatile String  tech_phone_ext = "";
	public volatile String  tech_fax = "";
	public volatile String  tech_fax_ext = "";
	public volatile String  tech_email = "";
	public volatile String  tech_email_domain_name = "";
	public volatile String  reseller_email = null;
	public volatile String  reseller_url = null;
	public volatile String  sponsoring_registrar_address = null;
	public volatile String  sponsoring_registrar_country = null;
	public volatile String  sponsoring_registrar_phone = null;
	public volatile String  sponsoring_registrar_contact = null;
	public volatile String  sponsoring_registrar_email = null;
	public volatile String  sponsoring_registrar_email_domain_name = null;
	public volatile String  sponsoring_registrar_admin_email = null;
	public volatile String  sponsoring_registrar_admin_email_domain_name = null;
	public volatile String  sponsoring_registrar_admin_contact = null;
	public volatile String  sponsoring_registrar_customer_service_contact = null;
	public volatile String  sponsoring_registrar_customer_service_email = null;
	public volatile String  sponsoring_registrar_customer_service_email_domain_name = null;

	public volatile String registrant_language = null;
	public volatile String admin_language = null;
	public volatile String tech_language = null;
	public volatile String billing_language = null;

	public volatile String domain_idn_name = null;

	/**.INFO*/
	public volatile String  billing_id = null;
	/**.INFO*/
	public volatile String  billing_name = null;
	/**.INFO*/
	public volatile String  billing_organization = null;
	/**.INFO*/
	public volatile String  billing_street = null;
	/**.INFO*/
	public volatile String  billing_city = null;
	/**.INFO*/
	public volatile String  billing_email = null;
	public volatile String  billing_email_domain_name = "";
	/**.INFO*/
	public volatile String  billing_state_province = null;
	/**.INFO*/
	public volatile String  billing_postal_code = null;
	/**.INFO*/
	public volatile String  billing_country = null;
	/**.INFO*/
	public volatile String  billing_phone = null;
	/**.INFO*/
	public volatile String  billing_phone_ext = null;
	/**.INFO*/
	public volatile String  billing_fax = null;
	/**.INFO*/
	public volatile String  billing_fax_ext = null;

	/**.fr*/
	public volatile String hold = null;
	/**.fr*/
	public volatile String holder_c = null;
	/**.fr*/
	public volatile String admin_c = null;
	/**.fr*/
	public volatile String tech_c = null;
	/**.fr*/
	public volatile String zone_c = null;
	/**.fr*/
	public volatile String nsl_id = null;
	/**.fr*/
	public volatile String source = null;
	/**.fr*/
	public volatile String ns_list = null;
	/**.fr*/
	public volatile String admin_anonymous = null;
	/**.fr*/
	public volatile String tech_anonymous = null;
	/**.fr*/
	public volatile String registrant_anonymous = null;
	/**.fr*/
	public volatile String admin_registered = null;
	/**.fr*/
	public volatile String tech_registered = null;
	/**.fr*/
	public volatile String registrant_registered = null;
	/**.fr*/
	public volatile String admin_changed = null;
	/**.fr*/
	public volatile String tech_changed = null;
	/**.fr*/
	public volatile String registrant_changed = null;
	/**.fr*/
	public volatile String admin_obsoleted = null;
	/**.fr*/
	public volatile String tech_obsoleted = null;
	/**.fr*/
	public volatile String registrant_obsoleted = null;
	/**.fr*/
	public volatile String nic_hdl = null;

	public volatile String  first_lookup_date = driver.time.getTime_Current_Hyphenated(false);
	public volatile String  last_lookup_date = driver.time.getTime_Current_Hyphenated(false);
	public volatile long first_lookup_date_millis = System.currentTimeMillis();
	public volatile long last_lookup_date_millis = System.currentTimeMillis();

	public volatile String value_map = "";


	/**We have room for 10 - 20 name servers, but only return a list of the allocated servers*/
	public volatile String name_server_concat = null;

	/**We have room for 5 - 10 domain status indicators but only return a list of the allocated status*/
	public volatile String domain_status_concat = null;




	//
	/////
	/////////
	////////////////
	//////////////////////////////
	
	
	public static final short SEARCH_VALUE_TLD = 0;
	public static final short SEARCH_VALUE_TLD_REGISTRAR_SERVER = 1;
	public static final short SEARCH_VALUE_DOMAIN_NAME_REGISTRAR_SERVER = 2;
	public static final short SEARCH_VALUE_DOMAIN_NAME = 3;
	public static final short SEARCH_VALUE_REGISTRY_DOMAIN_ID = 4;
	public static final short SEARCH_VALUE_REGISTRAR_WHOIS_SERVER = 5;
	public static final short SEARCH_VALUE_REGISTRAR_URL = 6;
	public static final short SEARCH_VALUE_UPDATED_DATE = 7;
	public static final short SEARCH_VALUE_CREATION_DATE = 8;
	public static final short SEARCH_VALUE_REGISTRAR_REGISTRATION_EXPIRATION_DATE = 9;
	public static final short SEARCH_VALUE_REGISTRAR = 10;
	public static final short SEARCH_VALUE_REGISTRAR_IANA_ID = 11;
	public static final short SEARCH_VALUE_REGISTRAR_ABUSE_CONTACT_EMAIL = 12;
	public static final short SEARCH_VALUE_REGISTRAR_ABUSE_CONTACT_PHONE = 13;
	public static final short SEARCH_VALUE_REGISTRAR_ABUSE_CONTACT_EXT = 14;
	public static final short SEARCH_VALUE_DOMAIN_STATUS = 15;
	public static final short SEARCH_VALUE_REGISTRY_REGISTRANT_ID = 16;
	public static final short SEARCH_VALUE_REGISTRANT_NAME = 17;
	public static final short SEARCH_VALUE_REGISTRANT_ORGANIZATION = 18;
	public static final short SEARCH_VALUE_REGISTRANT_STREET = 19;
	public static final short SEARCH_VALUE_REGISTRANT_CITY = 20;
	public static final short SEARCH_VALUE_REGISTRANT_STATE_PROVINCE = 21;
	public static final short SEARCH_VALUE_REGISTRANT_POSTAL_CODE = 22;
	public static final short SEARCH_VALUE_REGISTRANT_COUNTRY = 23;
	public static final short SEARCH_VALUE_REGISTRANT_PHONE = 24;
	public static final short SEARCH_VALUE_REGISTRANT_PHONE_EXT = 25;
	public static final short SEARCH_VALUE_REGISTRANT_FAX = 26;
	public static final short SEARCH_VALUE_REGISTRANT_FAX_EXT = 27;
	public static final short SEARCH_VALUE_REGISTRANT_EMAIL = 28;
	public static final short SEARCH_VALUE_REGISTRY_ADMIN_ID = 29;
	public static final short SEARCH_VALUE_ADMIN_NAME = 30;
	public static final short SEARCH_VALUE_ADMIN_ORGANIZATION = 31;
	public static final short SEARCH_VALUE_ADMIN_STREET = 32;
	public static final short SEARCH_VALUE_ADMIN_CITY = 33;
	public static final short SEARCH_VALUE_ADMIN_STATE_PROVINCE = 34;
	public static final short SEARCH_VALUE_ADMIN_POSTAL_CODE = 35;
	public static final short SEARCH_VALUE_ADMIN_COUNTRY = 36;
	public static final short SEARCH_VALUE_ADMIN_PHONE = 37;
	public static final short SEARCH_VALUE_ADMIN_PHONE_EXT = 38;
	public static final short SEARCH_VALUE_ADMIN_FAX = 39;
	public static final short SEARCH_VALUE_ADMIN_FAX_EXT = 40;
	public static final short SEARCH_VALUE_ADMIN_EMAIL = 41;
	public static final short SEARCH_VALUE_REGISTRY_TECH_ID = 42;
	public static final short SEARCH_VALUE_TECH_NAME = 43;
	public static final short SEARCH_VALUE_TECH_ORGANIZATION = 44;
	public static final short SEARCH_VALUE_TECH_STREET = 45;
	public static final short SEARCH_VALUE_TECH_CITY = 46;
	public static final short SEARCH_VALUE_TECH_STATE_PROVINCE = 47;
	public static final short SEARCH_VALUE_TECH_POSTAL_CODE = 48;
	public static final short SEARCH_VALUE_TECH_COUNTRY = 49;
	public static final short SEARCH_VALUE_TECH_PHONE = 50;
	public static final short SEARCH_VALUE_TECH_PHONE_EXT = 51;
	public static final short SEARCH_VALUE_TECH_FAX = 52;
	public static final short SEARCH_VALUE_TECH_FAX_EXT = 53;
	public static final short SEARCH_VALUE_TECH_EMAIL = 54;
	public static final short SEARCH_VALUE_NAME_SERVER = 55;
	public static final short SEARCH_VALUE_NAME_SERVER_IP = 56;
	public static final short SEARCH_VALUE_DNSSEC = 57;
	public static final short SEARCH_VALUE_WHOIS_SERVER = 58;
	public static final short SEARCH_VALUE_REFERRAL_URL = 59;
	public static final short SEARCH_VALUE_BILLING_ID = 60;
	public static final short SEARCH_VALUE_BILLING_NAME = 61;
	public static final short SEARCH_VALUE_BILLING_EMAIL = 62;
	public static final short SEARCH_VALUE_BILLING_ORGANIZATION = 63;
	public static final short SEARCH_VALUE_BILLING_STREET = 64;
	public static final short SEARCH_VALUE_BILLING_CITY = 65;
	public static final short SEARCH_VALUE_BILLING_STATE_PROVINCE = 66;
	public static final short SEARCH_VALUE_BILLING_POSTAL_CODE = 67;
	public static final short SEARCH_VALUE_BILLING_COUNTRY = 68;
	public static final short SEARCH_VALUE_BILLING_PHONE = 69;
	public static final short SEARCH_VALUE_BILLING_PHONE_EXT = 70;
	public static final short SEARCH_VALUE_BILLING_FAX = 71;
	public static final short SEARCH_VALUE_BILLING_FAX_EXT = 72;
	public static final short SEARCH_VALUE_FIRST_LOOKUP_DATE = 73;
	public static final short SEARCH_VALUE_LAST_LOOKUP_DATE = 74;
	public static final short SEARCH_VALUE_NSLOOKUP_REQUEST = 75;
	public static final short SEARCH_VALUE_NSLOOKUP_SERVER = 76;
	public static final short SEARCH_VALUE_NSLOOKUP_ADDRESS_1 = 77;
	public static final short SEARCH_VALUE_NSLOOKUP_NAME = 78;
	public static final short SEARCH_VALUE_NSLOOKUP_ADDRESS_2 = 79;
	public static final short SEARCH_VALUE_NSLOOKUP_IPV4_FIRST = 80;
	public static final short SEARCH_VALUE_NSLOOKUP_IPV6_FIRST = 81;
	public static final short SEARCH_VALUE_NSLOOKUP_IPV4 = 82;
	public static final short SEARCH_VALUE_NSLOOKUP_IPV6 = 83;
	public static final short SEARCH_VALUE_NSLOOKUP_LAST_RETRIEVED = 84;
	public static final short SEARCH_VALUE_NSLOOKUP_LAST_UPDATE_TIME = 85;
	public static final short SEARCH_VALUE_NSLOOKUP_AUTHORITATIVE = 86;
	public static final short SEARCH_VALUE_NSLOOKUP_SOURCE = 87;
	public static final short SEARCH_VALUE_GEOLOOKUP_REQUEST = 88;
	public static final short SEARCH_VALUE_GEOLOOKUP_IP = 89;
	public static final short SEARCH_VALUE_GEOLOOKUP_COUNTRY_CODE = 90;
	public static final short SEARCH_VALUE_GEOLOOKUP_COUNTRY_NAME = 91;
	public static final short SEARCH_VALUE_GEOLOOKUP_REGION_CODE = 92;
	public static final short SEARCH_VALUE_GEOLOOKUP_REGION_NAME = 93;
	public static final short SEARCH_VALUE_GEOLOOKUP_CITY = 94;
	public static final short SEARCH_VALUE_GEOLOOKUP_ZIP_CODE = 95;
	public static final short SEARCH_VALUE_GEOLOOKUP_TIME_ZONE = 96;
	public static final short SEARCH_VALUE_GEOLOOKUP_LATITUDE = 97;
	public static final short SEARCH_VALUE_GEOLOOKUP_LONGITUDE = 98;
	public static final short SEARCH_VALUE_GEOLOOKUP_METRO_CODE = 99;
	public static final short SEARCH_VALUE_GEOLOOKUP_LAST_UPDATE_TIME = 100;
	public static final short SEARCH_VALUE_GEOLOOKUP_LAST_RETRIEVED = 101;
	public static final short SEARCH_VALUE_GEOLOOKUP_SOURCE = 102;
	public static final short SEARCH_VALUE_GEOLOOKUP_AUTHORITATIVE = 103;
	
	public static final short SEARCH_VALUE_NAME = 104;
	public static final short SEARCH_VALUE_EMAIL = 105;
	public static final short SEARCH_VALUE_PHONE = 106;
	public static final short SEARCH_VALUE_FAX = 107;
	public static final short SEARCH_VALUE_ORG = 108;
	public static final short SEARCH_VALUE_COUNTRY = 109;
	public static final short SEARCH_VALUE_STATE = 110;
	public static final short SEARCH_VALUE_CITY = 111;
	public static final short SEARCH_VALUE_STREET = 112;
	public static final short SEARCH_VALUE_IP = 113;
	public static final short SEARCH_VALUE_SERVER = 114;
	public static final short SEARCH_VALUE_ID = 115;
	public static final short SEARCH_VALUE_URL = 116;

	public File fleExcaliburImportFile = null;
	public File fleExcaliburImportDirectory = null;
	volatile LinkedList<File> list_import_excalibur_data_file = null;
	BufferedReader brIn_excablibur_whois_import = null;
	Timer tmrReadExcaliburImportFile = null;
	public volatile boolean process_interrupt_read_excalibur_input_file = true;
	public volatile long num_excalibur_import_files = 0;
	public volatile long num_import_lines = 0;
	public volatile String [] array_excalibur_whois = null, arr2 = null;
	public volatile boolean PERFORM_GEO_IF_NOT_SPECIFIED = false;
	
	public File fle_IOC = null;
	public File fle_WHOIS_DNS_IMPORT_LIST = null;
	public boolean load_ioc_list = false;
	public boolean load_whois_dns_import_list = false;
	public volatile long added_indicators = 0;
	
	public volatile boolean new_ioc_entry = false;
	
	public Whois(String line)
	{
		try
		{
			if(line != null && !line.trim().equals("") && line.toLowerCase().contains(ioc_found.toLowerCase().trim()))
			{
				//e.g. * * * ALERT * * * malicious entry found on IOC	 [raglanroast.icu]				
				process_ioc(line);							
			}
			
			else if(line != null && !line.trim().equals(""))
			{
				//split and parse
				String [] array = line.split("\t");
				
				if(array != null && array.length > 0)
				{
					//parse
					for(String tuple : array)
						this.parse_whois_server(tuple);
				}
				
				//check if parse complete
				if(DOMAIN_NAME != null && !DOMAIN_NAME.toLowerCase().trim().equals("null") && !this.tree_whois_lookup.containsKey(DOMAIN_NAME.toLowerCase().trim()))
				{
					DOMAIN_NAME = DOMAIN_NAME.toLowerCase().trim();
					this.LOOKUP = DOMAIN_NAME;
					this.LOOKUP_ORIGINAL = DOMAIN_NAME;
					
					this.tree_whois_lookup.put(DOMAIN_NAME.toLowerCase().trim(), this);
					
					//
					//LOG
					//
					if(fleLog_Whois_Excalibur == null || !fleLog_Whois_Excalibur.exists() || !fleLog_Whois_Excalibur.isFile())
					{
						fleLog_Whois_Excalibur = new File(Driver.NAME + File.separator + "log" + File.separator + "excalibur_whois_data_file" + File.separator + "excalibur_whois_data_file_" + driver.get_time_stamp("_") + ".txt");
						
						try	{	fleLog_Whois_Excalibur.getParentFile().mkdirs();	}	catch(Exception e){}
						
						pwOut_Excalibur_Whois_Data_File = new PrintWriter(new FileWriter(fleLog_Whois_Excalibur), true);
					}
					
					pwOut_Excalibur_Whois_Data_File.println(line);
				}
				
				//
				//check if ioc
				//
				if(this.is_on_ioc)
				{
					log_self_on_ioc(line);
				}
				
			}
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "Constructor - line", e, false);
		}
	}
	
	public boolean log_self_on_ioc(String line)
	{
		try
		{
			is_on_ioc = true;
			
			//
			//queue
			//
			if(!this.list_ioc_whois.contains(this))
				this.list_ioc_whois.add(this);
			
			//
			//LOG
			//
			if(fleIOC_Alert_Whois == null || !fleIOC_Alert_Whois.exists() || !fleIOC_Alert_Whois.isFile())
			{
				fleIOC_Alert_Whois = new File(Driver.NAME + File.separator + "log" + File.separator + "ioc_alert_whois" + File.separator + "ioc_alert_whois" + driver.get_time_stamp("_") + ".txt");
				
				try	{	fleIOC_Alert_Whois.getParentFile().mkdirs();	}	catch(Exception e){}
				
				pwOut_IOC_Alert_Whois = new PrintWriter(new FileWriter(fleIOC_Alert_Whois), true);
			}
			
			if(line != null && !line.trim().equals(""))
				pwOut_IOC_Alert_Whois.println(line);
			else
				get_whois_data_line("\t");
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "log_self_on_ioc", e);
		}
		
		return false;
	}
	
	/**
	 * 
	 * @param delimiter
	 * @param nslookup_tuple
	 * @param geo_tuple
	 * @return
	 */
	public String get_whois_data_line(String delimiter, String nslookup_tuple, String geo_tuple)
	{
		try
		{
			delimiter = " " + delimiter;
			
			//check if found on new ioc list
			if(this.is_on_ioc)
			{
				return 
						"ALERT:\t" + "IOC" + delimiter + 
						"TLD:   " + this.TLD + delimiter + 
						"TLD Registrar Server:   " + this.TLD_WHOIS_REGISTRAR + delimiter + 
						"Domain Name Registrar Server:   " + this.REGISTRAR_WHOIS_SERVER + delimiter + 
						("Domain Name:   " + DOMAIN_NAME + "") + delimiter + 
						("Registry Domain ID:   " + registry_domain_id + "") + delimiter + 
						("Registrar Whois Server:   " + registrar_whois_server + "") + delimiter + 
						("Registrar Url:   " + registrar_url + "") + delimiter + 
						("Updated Date:   " + updated_date + "") + delimiter + 
						("Creation Date:   " + creation_date + "") + delimiter + 
						("Registrar Registration Expiration Date:   " + registrar_registration_expiration_date + "") + delimiter + 
						("Registrar:   " + registrar + "") + delimiter + 
						("Registrar Iana ID:   " + registrar_iana_id + "") + delimiter + 
						("Registrar Abuse Contact Email:   " + registrar_abuse_contact_email + "") + delimiter + 
						("Registrar Abuse Contact Phone:   " + registrar_abuse_contact_phone + "") + delimiter + 

						("registrar_abuse_contact_ext:   " + registrar_abuse_contact_ext + "") + delimiter + 

						
						
						(get_domain_status_list( " " + this.delimiter1, false)) + delimiter + 

						
						("Registry Registrant ID:   " + registry_registrant_id + "") + delimiter + 
						("Registrant Name:   " + registrant_name + "") + delimiter + 
						("Registrant Organization:   " + registrant_organization + "") + delimiter + 
						("Registrant Street:   " + registrant_street + "") + delimiter + 
						("Registrant City:   " + registrant_city + "") + delimiter + 
						("Registrant State Province:   " + registrant_state_province + "") + delimiter + 
						("Registrant Postal Code:   " + registrant_postal_code + "") + delimiter + 
						("Registrant Country:   " + registrant_country + "") + delimiter + 
						("Registrant Phone:   " + registrant_phone + "") + delimiter + 
						("Registrant Phone Ext:   " + registrant_phone_ext + "") + delimiter + 
						("Registrant Fax:   " + registrant_fax + "") + delimiter + 
						("Registrant Fax Ext:   " + registrant_fax_ext + "") + delimiter + 
						("Registrant Email:   " + registrant_email + "") + delimiter + 
						
						
						
						("Registry Admin ID:   " + registry_admin_id + "") + delimiter + 
						("Admin Name:   " + admin_name + "") + delimiter + 
						("Admin Organization:   " + admin_organization + "") + delimiter + 
						("Admin Street:   " + admin_street + "") + delimiter + 
						("Admin City:   " + admin_city + "") + delimiter + 
						("Admin State Province:   " + admin_state_province + "") + delimiter + 
						("Admin Postal Code:   " + admin_postal_code + "") + delimiter + 
						("Admin Country:   " + admin_country + "") + delimiter + 
						("Admin Phone:   " + admin_phone + "") + delimiter + 
						("Admin Phone Ext:   " + admin_phone_ext + "") + delimiter + 
						("Admin Fax:   " + admin_fax + "") + delimiter + 
						("Admin Fax Ext:   " + admin_fax_ext + "") + delimiter + 
						("Admin Email:   " + admin_email + "") + delimiter + 
						
						
						("Registry Tech ID:   " + registry_tech_id + "") + delimiter + 
						("Tech Name:   " + tech_name + "") + delimiter + 
						("Tech Organization:   " + tech_organization + "") + delimiter + 
						("Tech Street:   " + tech_street + "") + delimiter + 
						("Tech City:   " + tech_city + "") + delimiter + 
						("Tech State Province:   " + tech_state_province + "") + delimiter + 
						("Tech Postal Code:   " + tech_postal_code + "") + delimiter + 
						("Tech Country:   " + tech_country + "") + delimiter + 
						("Tech Phone:   " + tech_phone + "") + delimiter + 
						("Tech Phone Ext:   " + tech_phone_ext + "") + delimiter + 
						("Tech Fax:   " + tech_fax + "") + delimiter + 
						("Tech Fax Ext:   " + tech_fax_ext + "") + delimiter + 
						("Tech Email:   " + tech_email + "") + delimiter + 
						
						
						(this.get_name_server_list(" " + delimiter1 + " ", false, false)) + delimiter + 			
						
						(this.get_name_server_IP_list(" " + delimiter1 + " ", false, false)) + delimiter + 

						
						("DNSSEC:   " + dnssec + "") + delimiter + 
						
						
						("Whois Server:   " + whois_server + "") + delimiter + 
						
						("Referral URL:   " + referral_url + "") + delimiter + 

						("billing_id:   " + billing_id + "") + delimiter + 
						("billing_name:   " + billing_name + "") + delimiter + 
						("billing_email:   " + billing_email + "") + delimiter +
						("billing_organization:   " + billing_organization + "") + delimiter + 
						("billing_street:   " + billing_street + "") + delimiter + 
						("billing_city:   " + billing_city + "") + delimiter + 
						("billing_state_province:   " + billing_state_province + "") + delimiter + 
						("billing_postal_code:   " + billing_postal_code + "") + delimiter + 
						("billing_country:   " + billing_country + "") + delimiter + 
						("billing_phone:   " + billing_phone + "") + delimiter + 
						("billing_phone_ext:   " + billing_phone_ext + "") + delimiter + 
						("billing_fax:   " + billing_fax + "") + delimiter + 
						("billing_fax_ext:   " + billing_fax_ext + "") + delimiter + 
						
						("first lookup date:   " + first_lookup_date + "") + delimiter + 
						("last lookup date:   " + last_lookup_date + "") + delimiter +

						//nslookup
						nslookup_tuple + delimiter + 
						
						//geo
						geo_tuple  + delimiter +
						
						ioc_found + "\t--> \t" + ioc_listing_details;
												
			}
			
						
			return 
			"TLD:   " + this.TLD + delimiter + 
			"TLD Registrar Server:   " + this.TLD_WHOIS_REGISTRAR + delimiter + 
			"Domain Name Registrar Server:   " + this.REGISTRAR_WHOIS_SERVER + delimiter + 
			("Domain Name:   " + DOMAIN_NAME + "") + delimiter + 
			("Registry Domain ID:   " + registry_domain_id + "") + delimiter + 
			("Registrar Whois Server:   " + registrar_whois_server + "") + delimiter + 
			("Registrar Url:   " + registrar_url + "") + delimiter + 
			("Updated Date:   " + updated_date + "") + delimiter + 
			("Creation Date:   " + creation_date + "") + delimiter + 
			("Registrar Registration Expiration Date:   " + registrar_registration_expiration_date + "") + delimiter + 
			("Registrar:   " + registrar + "") + delimiter + 
			("Registrar Iana ID:   " + registrar_iana_id + "") + delimiter + 
			("Registrar Abuse Contact Email:   " + registrar_abuse_contact_email + "") + delimiter + 
			("Registrar Abuse Contact Phone:   " + registrar_abuse_contact_phone + "") + delimiter + 

			("registrar_abuse_contact_ext:   " + registrar_abuse_contact_ext + "") + delimiter + 

			
			
			(get_domain_status_list( " " + this.delimiter1, false)) + delimiter + 

			
			("Registry Registrant ID:   " + registry_registrant_id + "") + delimiter + 
			("Registrant Name:   " + registrant_name + "") + delimiter + 
			("Registrant Organization:   " + registrant_organization + "") + delimiter + 
			("Registrant Street:   " + registrant_street + "") + delimiter + 
			("Registrant City:   " + registrant_city + "") + delimiter + 
			("Registrant State Province:   " + registrant_state_province + "") + delimiter + 
			("Registrant Postal Code:   " + registrant_postal_code + "") + delimiter + 
			("Registrant Country:   " + registrant_country + "") + delimiter + 
			("Registrant Phone:   " + registrant_phone + "") + delimiter + 
			("Registrant Phone Ext:   " + registrant_phone_ext + "") + delimiter + 
			("Registrant Fax:   " + registrant_fax + "") + delimiter + 
			("Registrant Fax Ext:   " + registrant_fax_ext + "") + delimiter + 
			("Registrant Email:   " + registrant_email + "") + delimiter + 
			
			
			
			("Registry Admin ID:   " + registry_admin_id + "") + delimiter + 
			("Admin Name:   " + admin_name + "") + delimiter + 
			("Admin Organization:   " + admin_organization + "") + delimiter + 
			("Admin Street:   " + admin_street + "") + delimiter + 
			("Admin City:   " + admin_city + "") + delimiter + 
			("Admin State Province:   " + admin_state_province + "") + delimiter + 
			("Admin Postal Code:   " + admin_postal_code + "") + delimiter + 
			("Admin Country:   " + admin_country + "") + delimiter + 
			("Admin Phone:   " + admin_phone + "") + delimiter + 
			("Admin Phone Ext:   " + admin_phone_ext + "") + delimiter + 
			("Admin Fax:   " + admin_fax + "") + delimiter + 
			("Admin Fax Ext:   " + admin_fax_ext + "") + delimiter + 
			("Admin Email:   " + admin_email + "") + delimiter + 
			
			
			("Registry Tech ID:   " + registry_tech_id + "") + delimiter + 
			("Tech Name:   " + tech_name + "") + delimiter + 
			("Tech Organization:   " + tech_organization + "") + delimiter + 
			("Tech Street:   " + tech_street + "") + delimiter + 
			("Tech City:   " + tech_city + "") + delimiter + 
			("Tech State Province:   " + tech_state_province + "") + delimiter + 
			("Tech Postal Code:   " + tech_postal_code + "") + delimiter + 
			("Tech Country:   " + tech_country + "") + delimiter + 
			("Tech Phone:   " + tech_phone + "") + delimiter + 
			("Tech Phone Ext:   " + tech_phone_ext + "") + delimiter + 
			("Tech Fax:   " + tech_fax + "") + delimiter + 
			("Tech Fax Ext:   " + tech_fax_ext + "") + delimiter + 
			("Tech Email:   " + tech_email + "") + delimiter + 
			
			
			(this.get_name_server_list(" " + delimiter1 + " ", false, false)) + delimiter + 			
			
			(this.get_name_server_IP_list(" " + delimiter1 + " ", false, false)) + delimiter + 

			
			("DNSSEC:   " + dnssec + "") + delimiter + 
			
			
			("Whois Server:   " + whois_server + "") + delimiter + 
			
			("Referral URL:   " + referral_url + "") + delimiter + 

			("billing_id:   " + billing_id + "") + delimiter + 
			("billing_name:   " + billing_name + "") + delimiter + 
			("billing_email:   " + billing_email + "") + delimiter +
			("billing_organization:   " + billing_organization + "") + delimiter + 
			("billing_street:   " + billing_street + "") + delimiter + 
			("billing_city:   " + billing_city + "") + delimiter + 
			("billing_state_province:   " + billing_state_province + "") + delimiter + 
			("billing_postal_code:   " + billing_postal_code + "") + delimiter + 
			("billing_country:   " + billing_country + "") + delimiter + 
			("billing_phone:   " + billing_phone + "") + delimiter + 
			("billing_phone_ext:   " + billing_phone_ext + "") + delimiter + 
			("billing_fax:   " + billing_fax + "") + delimiter + 
			("billing_fax_ext:   " + billing_fax_ext + "") + delimiter + 
			
			("first lookup date:   " + first_lookup_date + "") + delimiter + 
			("last lookup date:   " + last_lookup_date + "") + delimiter +

			//nslookup
			nslookup_tuple + delimiter + 
			
			//geo
			geo_tuple;

		}
		catch(Exception e)
		{
			driver.eop(myClassName, "get_whois_data_line", e); 
		}
		
		return this.DOMAIN_NAME;
	}
	
	/**
	 * Created to account for nslookup and/or geo being null - handles all 3 cases
	 */
	public String get_whois_data_line(String delimiter)	
	{
		try
		{			
			if(this.node_geo != null && this.node_nslookup != null)
				return (this.get_whois_data_line(delimiter, this.node_nslookup.get_details(true, ":", delimiter), this.node_geo.get_details(true, ":", delimiter)));
			else if(this.node_geo != null)
				return (this.get_whois_data_line(delimiter, Node_Nslookup.BLANK_ROW, this.node_geo.get_details(true, ":", delimiter)));
			else if(this.node_nslookup != null)
				return (this.get_whois_data_line(delimiter, this.node_nslookup.get_details(true, ":", delimiter), Node_GeoIP.BLANK_ROW));									
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "get_whois_data_line", e);
		}
		
		return this.get_whois_data_line(delimiter, Node_Nslookup.BLANK_ROW, Node_GeoIP.BLANK_ROW);
	}
	
	public boolean parse_whois_server(String tuple)
	{
		try
		{
			if(tuple == null || tuple.trim().equals(""))
				return false;
			
			//avoid overwriting data...
			if(tuple.contains(":null") || tuple.contains(": null") || tuple.trim().endsWith(":") || tuple.trim().endsWith("null"))
				return false;
			
			if(tuple.trim().startsWith("%") || tuple.trim().startsWith("\\#"))
				return false;
			
			if(tuple.toLowerCase().trim().startsWith("no match for \""))
			{
				try
				{
					if(!tree_not_found_cache.containsKey(DOMAIN_NAME))
					{
						tree_not_found_cache.put(DOMAIN_NAME, DOMAIN_NAME);												
					}
										
				}
				catch(Exception e)
				{
					
				}
				
				
				return false;
			}
			
			//dismiss invalid tuples
			if(!tuple.contains(":"))
			{
				check_special_parsing(tuple);
				
				return false;
			}  
			
			tuple = tuple.trim();
			
			if(tuple.startsWith("Nameserver:"))
				tuple = tuple.replaceFirst("Nameserver", "name server");
			else if(tuple.startsWith("Nameserver:"))
				tuple = tuple.replaceFirst("Nameserver", "name server");
			else if(tuple.startsWith("nserver:"))
				tuple = tuple.replaceFirst("nserver", "name server");
			else if(tuple.startsWith("IP Address:"))
				tuple = tuple.replaceFirst("IP Address", "name server ip");
			
			
			
			//create alias for the below to work properly
			//if(tuple.toLowerCase().trim().startsWith("status:"))
			//	tuple = "domain " + tuple;
			
			//Search
			if(tuple.toLowerCase().startsWith("whois:"))
			{
				TLD_WHOIS_REGISTRAR_FULL_LINE = tuple.trim();
				TLD_WHOIS_REGISTRAR = tuple.substring(6).trim();		
				
				//found what we're looking for, store in the cache
				cache_IANA_TLD.put(TLD,  this);								
			}
			
			else if(tuple.toLowerCase().startsWith("alert"))
			{
				is_on_ioc = true;
				this.list_ioc_whois.add(this);
			}
			
			else if(tuple.toLowerCase().startsWith("ioc_"))
			{
				is_on_ioc = true;

				if(this.list_ioc_detection_listing == null)
					list_ioc_detection_listing = new LinkedList<String>();
				
				if(!list_ioc_detection_listing.contains(tuple))
				{
					list_ioc_detection_listing.add(tuple);
					
					this.ioc_listing_details = ioc_listing_details + tuple + "\t";
				}
			}
			
			else if(tuple.toLowerCase().startsWith("tld"))
				this.TLD = tuple.substring(4);
			
			else if(tuple.toLowerCase().startsWith("tld registrar server"))
			{
				this.TLD_WHOIS_REGISTRAR = tuple.substring(13);
				
				if(!this.cache_IANA_TLD.containsKey(TLD))
					this.cache_IANA_TLD.put(TLD,  this);
			}
			
			else if(tuple.toLowerCase().startsWith("domain name:"))
			{
				if(tuple.toLowerCase().trim().replaceAll("domain name:", "").equals(""))
					return false;
				
				DOMAIN_NAME = tuple.substring(12).toLowerCase().trim();
				
								
				//update_tld_and_tld_registrar_if_applicable();
				
				store_mode_DOMAIN_NAME = true;
				
				this.store_mode_ADMINISTRATOR = false;
				this.store_mode_DATA_VALIDATION = false;
				
				this.store_mode_NAME_SERVERS = false;
				this.store_mode_REGISTRANT = false;
				this.store_mode_REGISTRANT_ADDRESS = false;
				this.store_mode_REGISTRANT_TYPE = false;
				this.store_mode_REGISTRAR = false;
				this.store_mode_REGISTRATION_STATUS = false;
				this.store_mode_RELEVANT_DATES = false;
				this.store_mode_TECHNICAL = false;
			}
			
			else if(tuple.toLowerCase().startsWith("domain:"))
			{
				DOMAIN_NAME = tuple.substring(7).toLowerCase().trim();
				
				//update_tld_and_tld_registrar_if_applicable();
			}
			
			else if(tuple.toLowerCase().startsWith("registry domain id:"))
				this.registry_domain_id = tuple.substring(19).trim();
			
			else if(tuple.toLowerCase().startsWith("domain id:"))
				this.registry_domain_id = tuple.substring(10).trim();
			
			else if(tuple.toLowerCase().startsWith("registrar whois server:"))
			{
				this.registrar_whois_server = tuple.substring(23).trim();
				REGISTRAR_WHOIS_SERVER = registrar_whois_server;
			}
			
			else if(tuple.toLowerCase().startsWith("domain name registrar server:"))
			{
				this.registrar_whois_server = tuple.substring(29).trim();
				REGISTRAR_WHOIS_SERVER = registrar_whois_server;
			}
			
			else if(tuple.toLowerCase().startsWith("reseller:"))
				this.reseller = tuple.substring(8).trim();
			
			else if(tuple.toLowerCase().startsWith("registrar url:"))
				this.registrar_url = tuple.substring(14).trim();
			
			else if(tuple.toLowerCase().startsWith("sponsoring registrar url:"))
				this.registrar_url = tuple.substring(25).trim();
			
			else if(tuple.toLowerCase().startsWith("updated date:"))
				this.updated_date = tuple.substring(13).trim();
			
			else if(tuple.toLowerCase().startsWith("last updated date:"))
				this.updated_date = tuple.substring(18).trim();
			
			else if(tuple.toLowerCase().startsWith("update date:"))
				this.updated_date = tuple.substring(12).trim();
			
			else if(tuple.toLowerCase().startsWith("relevant dates:"))
				this.updated_date = tuple.substring(15).trim();
			
			else if(tuple.toLowerCase().startsWith("type:"))
			{
				value = tuple.toLowerCase().trim().substring(5).trim();
				
				if(value.startsWith("isp"))
				{
					this.store_mode_TECHNICAL = true;					
					this.store_mode_ADMINISTRATOR = false;
					this.store_mode_DATA_VALIDATION = false;
					this.store_mode_DOMAIN_NAME = false;
					this.store_mode_NAME_SERVERS = false;
					this.store_mode_REGISTRANT = false;
					this.store_mode_REGISTRANT_ADDRESS = false;
					this.store_mode_REGISTRANT_TYPE = false;
					this.store_mode_REGISTRAR = false;
					this.store_mode_REGISTRATION_STATUS = false;
					this.store_mode_RELEVANT_DATES = false;
				}
				
				else if(value.startsWith("org"))
				{
					this.store_mode_TECHNICAL = false;					
					this.store_mode_ADMINISTRATOR = true;
					this.store_mode_DATA_VALIDATION = false;
					this.store_mode_DOMAIN_NAME = false;
					this.store_mode_NAME_SERVERS = false;
					this.store_mode_REGISTRANT = false;
					this.store_mode_REGISTRANT_ADDRESS = false;
					this.store_mode_REGISTRANT_TYPE = false;
					this.store_mode_REGISTRAR = false;
					this.store_mode_REGISTRATION_STATUS = false;
					this.store_mode_RELEVANT_DATES = false;
				}
				
				else if(value.startsWith("person"))
				{
					this.store_mode_TECHNICAL = false;					
					this.store_mode_ADMINISTRATOR = false;
					this.store_mode_DATA_VALIDATION = false;
					this.store_mode_DOMAIN_NAME = false;
					this.store_mode_NAME_SERVERS = false;
					this.store_mode_REGISTRANT = true;
					this.store_mode_REGISTRANT_ADDRESS = false;
					this.store_mode_REGISTRANT_TYPE = false;
					this.store_mode_REGISTRAR = false;
					this.store_mode_REGISTRATION_STATUS = false;
					this.store_mode_RELEVANT_DATES = false;
				}
			}
			
			else if(tuple.toLowerCase().startsWith("registration status:"))
			{
				this.registration_status = tuple.substring(20).trim();
				
				store_mode_REGISTRATION_STATUS = true;
				
				this.store_mode_ADMINISTRATOR = false;
				this.store_mode_DATA_VALIDATION = false;
				this.store_mode_DOMAIN_NAME = false;
				this.store_mode_NAME_SERVERS = false;
				this.store_mode_REGISTRANT = false;
				this.store_mode_REGISTRANT_ADDRESS = false;
				this.store_mode_REGISTRANT_TYPE = false;
				this.store_mode_REGISTRAR = false;

				this.store_mode_RELEVANT_DATES = false;
				this.store_mode_TECHNICAL = false;
			}
			
			else if(tuple.toLowerCase().startsWith("state:"))
			{
				this.registration_status = tuple.substring(6).trim();
				
				store_mode_REGISTRATION_STATUS = true;
				
				this.store_mode_ADMINISTRATOR = false;
				this.store_mode_DATA_VALIDATION = false;
				this.store_mode_DOMAIN_NAME = false;
				this.store_mode_NAME_SERVERS = false;
				this.store_mode_REGISTRANT = false;
				this.store_mode_REGISTRANT_ADDRESS = false;
				this.store_mode_REGISTRANT_TYPE = false;
				this.store_mode_REGISTRAR = false;

				this.store_mode_RELEVANT_DATES = false;
				this.store_mode_TECHNICAL = false;
			}
			
			else if(tuple.toLowerCase().contains("last update of whois database:"))
			try	{		this.updated_date = tuple.toLowerCase().replaceAll("last update of whois database:", "").replaceAll("\\<", "").replaceAll("\\>", "").trim();	}	catch(Exception e){updated_date = tuple;}
			
			else if(tuple.toLowerCase().startsWith("last updated on:"))
				this.updated_date = tuple.substring(16).trim();
			
			else if(tuple.toLowerCase().startsWith("last-update:"))
				this.updated_date = tuple.substring(12).trim();
			
			else if(tuple.toLowerCase().startsWith("last updated on"))
				this.updated_date = tuple.substring(15).trim();
			
			else if(tuple.toLowerCase().startsWith("last updated:"))
				this.updated_date = tuple.substring(13).trim();
			
			else if(tuple.toLowerCase().startsWith("last update:"))
				this.updated_date = tuple.substring(12).trim();
			
			else if(tuple.toLowerCase().startsWith("source:"))
				this.source = tuple.substring(7).trim();
			
			else if(tuple.toLowerCase().startsWith("create date:"))
				this.creation_date = tuple.substring(12).trim();
				
			
			else if(tuple.toLowerCase().startsWith("creation date:"))
			{
				this.creation_date = tuple.substring(14).trim();
				
				//sometimes, this is provided by TLD registrar leaving REGISTRAR_WHOIS_SERVER blank. if so, store it here
				if(REGISTRAR_WHOIS_SERVER == null || REGISTRAR_WHOIS_SERVER.trim().equals(""))
					REGISTRAR_WHOIS_SERVER = TLD_WHOIS_REGISTRAR;
			}
			
			else if(tuple.toLowerCase().startsWith("registered on:"))
			{
				this.creation_date = tuple.substring(14).trim();
				
				//sometimes, this is provided by TLD registrar leaving REGISTRAR_WHOIS_SERVER blank. if so, store it here
				if(REGISTRAR_WHOIS_SERVER == null || REGISTRAR_WHOIS_SERVER.trim().equals(""))
					REGISTRAR_WHOIS_SERVER = TLD_WHOIS_REGISTRAR;
			}
			
			else if(tuple.toLowerCase().startsWith("created on:"))
			{
				this.creation_date = tuple.substring(11).trim();
				
				//sometimes, this is provided by TLD registrar leaving REGISTRAR_WHOIS_SERVER blank. if so, store it here
				if(REGISTRAR_WHOIS_SERVER == null || REGISTRAR_WHOIS_SERVER.trim().equals(""))
					REGISTRAR_WHOIS_SERVER = TLD_WHOIS_REGISTRAR;
			}
			
			else if(tuple.toLowerCase().startsWith("created:"))
			{
				this.creation_date = tuple.substring(8).trim();
				
				//sometimes, this is provided by TLD registrar leaving REGISTRAR_WHOIS_SERVER blank. if so, store it here
				if(REGISTRAR_WHOIS_SERVER == null || REGISTRAR_WHOIS_SERVER.trim().equals(""))
					REGISTRAR_WHOIS_SERVER = TLD_WHOIS_REGISTRAR;
			}
			
			else if(tuple.toLowerCase().startsWith("registry expiry date:"))
				this.registrar_registration_expiration_date = tuple.substring(21).trim();
			
			else if(tuple.toLowerCase().startsWith("registrar registration expiration date:"))
				this.registrar_registration_expiration_date = tuple.substring(39).trim();
			
			else if(tuple.toLowerCase().startsWith("paid-till:"))
				this.registrar_registration_expiration_date = tuple.substring(10).trim();
			
			else if(tuple.toLowerCase().startsWith("paid till:"))
				this.registrar_registration_expiration_date = tuple.substring(10).trim();
			
			else if(tuple.toLowerCase().startsWith("free-date:"))
				this.registrar_registration_expiration_date = tuple.substring(10).trim();
			
			else if(tuple.toLowerCase().startsWith("free date:"))
				this.registrar_registration_expiration_date = tuple.substring(10).trim();
			
			else if(tuple.toLowerCase().startsWith("expiration date:"))
				this.registrar_registration_expiration_date = tuple.substring(16).trim();
			
			else if(tuple.toLowerCase().startsWith("redemption expiry date:"))
				this.registrar_registration_expiration_date = tuple.substring(23).trim();
			
			else if(tuple.toLowerCase().startsWith("expiry date:"))
				this.registrar_registration_expiration_date = tuple.substring(12).trim();
			
			else if(tuple.toLowerCase().startsWith("reason:"))
				this.reason = tuple.substring(7).trim();
			
			else if(tuple.toLowerCase().startsWith("registrar:"))
			{
				if(registrar == null || registrar.trim().equals(""))
					registrar = tuple.substring(10).trim();
				/*else 
					registrar = registrar.trim() + " " + tuple.substring(10).trim();*/
				
				//this.registrar = tuple.substring(10).trim();
				
				store_mode_REGISTRAR = true;
				
				this.store_mode_ADMINISTRATOR = false;
				this.store_mode_DATA_VALIDATION = false;
				this.store_mode_DOMAIN_NAME = false;
				this.store_mode_NAME_SERVERS = false;
				this.store_mode_REGISTRANT = false;
				this.store_mode_REGISTRANT_ADDRESS = false;
				this.store_mode_REGISTRANT_TYPE = false;

				this.store_mode_REGISTRATION_STATUS = false;
				this.store_mode_RELEVANT_DATES = false;
				this.store_mode_TECHNICAL = false;
			}
			
			else if(tuple.toLowerCase().startsWith("sponsoring registrar:"))
				this.registrar = tuple.substring(21).trim();
			
			else if(tuple.toLowerCase().startsWith("registrar iana id:"))
				this.registrar_iana_id = tuple.substring(18).trim();
			
			else if(tuple.toLowerCase().startsWith("sponsoring registrar iana id:"))
				this.registrar_iana_id = tuple.substring(29).trim();
			
			else if(tuple.toLowerCase().startsWith("registrar abuse contact email:"))
			{
				this.registrar_abuse_contact_email = tuple.substring(30).trim();
				
				try
				{
					if(registrar_abuse_contact_email.contains("@"))
					{
						registrar_abuse_contact_email_domain_name = registrar_abuse_contact_email.substring(registrar_abuse_contact_email.lastIndexOf("@")+1);												
					}
				}
				catch(Exception ee){}
				
			}
			
			else if(tuple.toLowerCase().startsWith("sponsoring registrar abuse email:"))
			{
				this.registrar_abuse_contact_email = tuple.substring(33).trim();
				
				try
				{
					if(registrar_abuse_contact_email.contains("@"))
					{
						registrar_abuse_contact_email_domain_name = registrar_abuse_contact_email.substring(registrar_abuse_contact_email.lastIndexOf("@")+1);												
					}
				}
				catch(Exception ee){}
			}
			
			else if(tuple.toLowerCase().startsWith("registrar_abuse_contact_ext:"))
				this.registrar_abuse_contact_ext = tuple.substring(28).trim();
			
			else if(tuple.toLowerCase().startsWith("registrar abuse contact phone:"))
				this.registrar_abuse_contact_phone = tuple.substring(30).trim();
			
			else if(tuple.toLowerCase().startsWith("sponsoring registrar abuse phone:"))
				this.registrar_abuse_contact_phone = tuple.substring(33).trim();
			
			else if(tuple.toLowerCase().startsWith("registrar abuse contact ext:"))
				this.registrar_abuse_contact_ext = tuple.substring(28).trim();
			
			else if(tuple.toLowerCase().startsWith("domain status:"))
			{
				if(domain_status1 == null)
					this.domain_status1 = tuple.substring(14).trim();
				
				else if(domain_status2 == null)
					this.domain_status2 = tuple.substring(14).trim();
				
				else if(domain_status3 == null)
					this.domain_status3 = tuple.substring(14).trim();
				
				else if(domain_status4 == null)
					this.domain_status4 = tuple.substring(14).trim();
				
				else if(domain_status5 == null)
					this.domain_status5 = tuple.substring(14).trim();
				
				else if(domain_status6 == null)
					this.domain_status6 = tuple.substring(14).trim();
				
				else if(domain_status7 == null)
					this.domain_status7 = tuple.substring(14).trim();
				
				else if(domain_status8 == null)
					this.domain_status8 = tuple.substring(14).trim();
				
				else if(domain_status9 == null)
					this.domain_status9 = tuple.substring(14).trim();
				
				else if(domain_status10 == null)
					this.domain_status10 = tuple.substring(14).trim();
			}
			

			else if(tuple.toLowerCase().startsWith("hold:"))
				hold = tuple.substring(5);
			
			else if(tuple.toLowerCase().startsWith("holder-c:"))
				holder_c = tuple.substring(9);
			
			else if(tuple.toLowerCase().startsWith("admin-c:"))
				admin_c = tuple.substring(8);
			
			else if(tuple.toLowerCase().startsWith("tech-c:"))
				tech_c = tuple.substring(7);
			
			else if(tuple.toLowerCase().startsWith("zone-c:"))
				zone_c = tuple.substring(7);
			
			else if(tuple.toLowerCase().startsWith("nsl-id:"))
				nsl_id = tuple.substring(7);
			
			else if(tuple.toLowerCase().startsWith("ns-list:"))
				ns_list = tuple.substring(8);
			
			else if(tuple.toLowerCase().startsWith("status:"))
			{
				if(domain_status1 == null)
					this.domain_status1 = tuple.substring(7).trim();
				
				else if(domain_status2 == null)
					this.domain_status2 = tuple.substring(7).trim();
				
				else if(domain_status3 == null)
					this.domain_status3 = tuple.substring(7).trim();
				
				else if(domain_status4 == null)
					this.domain_status4 = tuple.substring(7).trim();
				
				else if(domain_status5 == null)
					this.domain_status5 = tuple.substring(7).trim();
				
				else if(domain_status6 == null)
					this.domain_status6 = tuple.substring(7).trim();
				
				else if(domain_status7 == null)
					this.domain_status7 = tuple.substring(7).trim();
				
				else if(domain_status8 == null)
					this.domain_status8 = tuple.substring(7).trim();
				
				else if(domain_status9 == null)
					this.domain_status9 = tuple.substring(7).trim();
				
				else if(domain_status10 == null)
					this.domain_status10 = tuple.substring(7).trim();
			}
			
			else if(tuple.contains("        ") && tuple.contains("       "))
			{
				if(tuple.toLowerCase().startsWith("org:"))
				{
					this.registrant_organization = tuple.substring(4).trim();
					return true;
				}
				
				parse_name_server(tuple);
			}
			
			else if(tuple.toLowerCase().startsWith("name servers:"))
			{
				//only do so if tuple is empty
				if(tuple.toLowerCase().replaceAll("name servers:", "").trim().equals(""))
				{
					store_mode_NAME_SERVERS = true;
					
					this.store_mode_ADMINISTRATOR = false;
					this.store_mode_DATA_VALIDATION = false;
					this.store_mode_DOMAIN_NAME = false;
					this.store_mode_REGISTRANT = false;
					this.store_mode_REGISTRANT_ADDRESS = false;
					this.store_mode_REGISTRANT_TYPE = false;
					this.store_mode_REGISTRAR = false;
					this.store_mode_REGISTRATION_STATUS = false;
					this.store_mode_RELEVANT_DATES = false;
					this.store_mode_TECHNICAL = false;
				}
				
				if(tuple.substring(13).trim().length() < 2)
					return false;
				
				if(name_server_NAME1 == null)
				{
					this.name_server_NAME1 = tuple.substring(12).trim();
					
				}
				
				
			}
				
			
			else if(tuple.toLowerCase().startsWith("name server:") || tuple.toLowerCase().startsWith("server name:"))
			{
				//only do so if tuple is empty
				if(tuple.toLowerCase().replaceAll("name server:", "").trim().equals("") || tuple.toLowerCase().replaceAll("server name:", "").trim().equals(""))
				{
					store_mode_NAME_SERVERS = true;
					
					this.store_mode_ADMINISTRATOR = false;
					this.store_mode_DATA_VALIDATION = false;
					this.store_mode_DOMAIN_NAME = false;
					
					this.store_mode_REGISTRANT = false;
					this.store_mode_REGISTRANT_ADDRESS = false;
					this.store_mode_REGISTRANT_TYPE = false;
					this.store_mode_REGISTRAR = false;
					this.store_mode_REGISTRATION_STATUS = false;
					this.store_mode_RELEVANT_DATES = false;
					this.store_mode_TECHNICAL = false;
				}
				
				value = tuple.substring(12);
				
				if(this.list_name_server_names.contains(value))
					return false;				
					this.list_name_server_names.add(value);
				
				if(name_server_NAME1 == null)
				{
					this.name_server_NAME1 = tuple.substring(12).trim();
					
					
				}
				
				else if(name_server_NAME2 == null)
				{
					this.name_server_NAME2 = tuple.substring(12).trim();
					
					
				}
				
				else if(name_server_NAME3 == null)
				{
					this.name_server_NAME3 = tuple.substring(12).trim();

					
				}
				
				else if(name_server_NAME4 == null)
				{
					this.name_server_NAME4 = tuple.substring(12).trim();

				}
				
				else if(name_server_NAME5 == null)
				{
					this.name_server_NAME5 = tuple.substring(12).trim();

				}
				
				else if(name_server_NAME6 == null)
				{
					this.name_server_NAME6 = tuple.substring(12).trim();

				}
				
				else if(name_server_NAME7 == null)
				{
					this.name_server_NAME7 = tuple.substring(12).trim();

				}
				
				else if(name_server_NAME8 == null)
				{
					this.name_server_NAME8 = tuple.substring(12).trim();

				}
				
				else if(name_server_NAME9 == null)
				{
					this.name_server_NAME9 = tuple.substring(12).trim();

				}
				
				else if(name_server_NAME10 == null)
				{
					this.name_server_NAME10 = tuple.substring(12).trim();

				}
				
				else if(name_server_NAME11 == null)
				{
					this.name_server_NAME11 = tuple.substring(12).trim();
				}
				
				else if(name_server_NAME12 == null)
				{
					this.name_server_NAME12 = tuple.substring(12).trim();

				}
				
				else if(name_server_NAME13 == null)
				{
					this.name_server_NAME13 = tuple.substring(12).trim();

				}
				
				else if(name_server_NAME14 == null)
				{
					this.name_server_NAME14 = tuple.substring(12).trim();

				}
				
				else if(name_server_NAME15 == null)
				{
					this.name_server_NAME15 = tuple.substring(12).trim();
	
				}
				
				else if(name_server_NAME16 == null)
				{
					this.name_server_NAME16 = tuple.substring(12).trim();

				}
				
				else if(name_server_NAME17 == null)
				{
					this.name_server_NAME17 = tuple.substring(12).trim();

				}
				
				else if(name_server_NAME18 == null)
				{
					this.name_server_NAME18 = tuple.substring(12).trim();

				}
				
				else if(name_server_NAME19 == null)
				{
					this.name_server_NAME19 = tuple.substring(12).trim();

				}
				
				else if(name_server_NAME20 == null)
				{
					this.name_server_NAME20 = tuple.substring(12).trim();

				}
			}
			
			else if(tuple.toLowerCase().startsWith("name server ip:"))
			{
				if(name_server_IP1 == null)
				{
					this.name_server_IP1 = tuple.substring(15).trim();
					//this.name_server_IP1 = this.ping(this.name_server_IP1, PING_COUNT, false);
				}
				
				else if(name_server_IP2 == null)
				{
					this.name_server_IP2 = tuple.substring(15).trim();
					//this.name_server_IP2 = this.ping(this.name_server_IP2, PING_COUNT, false);
				}
				
				else if(name_server_IP3 == null)
				{
					this.name_server_IP3 = tuple.substring(15).trim();
					//this.name_server_IP3 = this.ping(this.name_server_IP3, PING_COUNT, false);
				}
				
				else if(name_server_IP4 == null)
				{
					this.name_server_IP4 = tuple.substring(15).trim();
					//this.name_server_IP4 = this.ping(this.name_server_IP4, PING_COUNT, false);
				}
				
				else if(name_server_IP5 == null)
				{
					this.name_server_IP5 = tuple.substring(15).trim();
					//this.name_server_IP5 = this.ping(this.name_server_IP5, PING_COUNT, false);
				}
				
				else if(name_server_IP6 == null)
				{
					this.name_server_IP6 = tuple.substring(15).trim();
					//this.name_server_IP6 = this.ping(this.name_server_IP6, PING_COUNT, false);
				}
				
				else if(name_server_IP7 == null)
				{
					this.name_server_IP7 = tuple.substring(15).trim();
					//this.name_server_IP7 = this.ping(this.name_server_IP7, PING_COUNT, false);
				}
				
				else if(name_server_IP8 == null)
				{
					this.name_server_IP8 = tuple.substring(15).trim();
					//this.name_server_IP8 = this.ping(this.name_server_IP8, PING_COUNT, false);
				}
				
				else if(name_server_IP9 == null)
				{
					this.name_server_IP9 = tuple.substring(15).trim();
					//this.name_server_IP9 = this.ping(this.name_server_IP9, PING_COUNT, false);
				}
				
				else if(name_server_IP10 == null)
				{
					this.name_server_IP10 = tuple.substring(15).trim();
					//this.name_server_IP10 = this.ping(this.name_server_IP10, PING_COUNT, false);
				}
				
				else if(name_server_IP11 == null)
				{
					this.name_server_IP11 = tuple.substring(15).trim();
					//this.name_server_IP11 = this.ping(this.name_server_IP11, PING_COUNT, false);
				}
				
				else if(name_server_IP15 == null)
				{
					this.name_server_IP15 = tuple.substring(15).trim();
					//this.name_server_IP15 = this.ping(this.name_server_IP15, PING_COUNT, false);
				}
				
				else if(name_server_IP13 == null)
				{
					this.name_server_IP13 = tuple.substring(15).trim();
					//this.name_server_IP13 = this.ping(this.name_server_IP13, PING_COUNT, false);
				}
				
				else if(name_server_IP14 == null)
				{
					this.name_server_IP14 = tuple.substring(15).trim();
					//this.name_server_IP14 = this.ping(this.name_server_IP14, PING_COUNT, false);
				}
				
				else if(name_server_IP15 == null)
				{
					this.name_server_IP15 = tuple.substring(15).trim();
					//this.name_server_IP15 = this.ping(this.name_server_IP15, PING_COUNT, false);		
				}
				
				else if(name_server_IP16 == null)
				{
					this.name_server_IP16 = tuple.substring(15).trim();
					//this.name_server_IP16 = this.ping(this.name_server_IP16, PING_COUNT, false);
				}
				
				else if(name_server_IP17 == null)
				{
					this.name_server_IP17 = tuple.substring(15).trim();
					//this.name_server_IP17 = this.ping(this.name_server_IP17, PING_COUNT, false);
				}
				
				else if(name_server_IP18 == null)
				{
					this.name_server_IP18 = tuple.substring(15).trim();
					//this.name_server_IP18 = this.ping(this.name_server_IP18, PING_COUNT, false);
				}
				
				else if(name_server_IP19 == null)
				{
					this.name_server_IP19 = tuple.substring(15).trim();
					//this.name_server_IP19 = this.ping(this.name_server_IP19, PING_COUNT, false);
				}
				
				else if(name_server_IP20 == null)
				{
					this.name_server_IP20 = tuple.substring(15).trim();
					//this.name_server_IP20 = this.ping(this.name_server_IP20, PING_COUNT, false);
				}
			}
			
			else if(tuple.toLowerCase().startsWith("dnssec:"))
				this.dnssec = tuple.substring(7).trim();
			
			/*else if(tuple.toLowerCase().startsWith("registrar registration expiration date:"))
				this.registrar_registration_expiration_date = tuple.substring(39).trim();*/ //<-- see registry_expiry_date
			
			else if(tuple.toLowerCase().startsWith("whois server:"))
				this.whois_server = tuple.substring(13).trim();
			
			else if(tuple.toLowerCase().startsWith("referral url:"))
				this.referral_url = tuple.substring(13).trim();
			
			else if(tuple.toLowerCase().startsWith("registrant id:"))
				this.registry_registrant_id = tuple.substring(14).trim();
			
			else if(tuple.toLowerCase().startsWith("registry registrant id:"))
				this.registry_registrant_id = tuple.substring(23).trim();
			
			else if(tuple.toLowerCase().startsWith("desc:"))
				this.registrant_name = registrant_name + tuple.substring(5).trim();
			
			else if(tuple.toLowerCase().startsWith("registrant name:"))
				this.registrant_name = tuple.substring(16).trim();
			
			else if(tuple.toLowerCase().startsWith("registrant:"))
			{																
				if(DOMAIN_NAME != null && !DOMAIN_NAME.trim().equals(""))
					tree_whois_registrar_server.put(DOMAIN_NAME, this);
				
				this.REGISTRAR_WHOIS_SERVER = this.TLD_WHOIS_REGISTRAR;
				
				if(registrar == null || registrar.trim().equals(""))
					this.registrar = REGISTRAR_WHOIS_SERVER;
				
				if(DOMAIN_NAME != null && !DOMAIN_NAME.trim().equals(""))
					this.tree_whois_lookup.put(DOMAIN_NAME, this);
				
				if(registrant_name == null)
					this.registrant_name = tuple.substring(11).trim();
				else
					this.registrant_name = registrant_name.trim() + " " + tuple.substring(11).trim();
				
				store_mode_REGISTRANT = true;
				
				this.store_mode_ADMINISTRATOR = false;
				this.store_mode_DATA_VALIDATION = false;
				this.store_mode_DOMAIN_NAME = false;
				this.store_mode_NAME_SERVERS = false;

				this.store_mode_REGISTRANT_ADDRESS = false;
				this.store_mode_REGISTRANT_TYPE = false;
				this.store_mode_REGISTRAR = false;
				this.store_mode_REGISTRATION_STATUS = false;
				this.store_mode_RELEVANT_DATES = false;
				this.store_mode_TECHNICAL = false;
			}
			
			else if(tuple.toLowerCase().startsWith("technical:"))
			{
				this.store_mode_TECHNICAL = true;
				
				this.store_mode_ADMINISTRATOR = false;
				this.store_mode_DATA_VALIDATION = false;
				this.store_mode_DOMAIN_NAME = false;
				this.store_mode_NAME_SERVERS = false;
				this.store_mode_REGISTRANT = false;
				this.store_mode_REGISTRANT_ADDRESS = false;
				this.store_mode_REGISTRANT_TYPE = false;
				this.store_mode_REGISTRAR = false;
				this.store_mode_REGISTRATION_STATUS = false;
				this.store_mode_RELEVANT_DATES = false;

			}
			
			else if(tuple.toLowerCase().startsWith("admin:"))
			{
				this.store_mode_ADMINISTRATOR = true;
				
				this.store_mode_DATA_VALIDATION = false;
				this.store_mode_DOMAIN_NAME = false;
				this.store_mode_NAME_SERVERS = false;
				this.store_mode_REGISTRANT = false;
				this.store_mode_REGISTRANT_ADDRESS = false;
				this.store_mode_REGISTRANT_TYPE = false;
				this.store_mode_REGISTRAR = false;
				this.store_mode_REGISTRATION_STATUS = false;
				this.store_mode_RELEVANT_DATES = false;
				this.store_mode_TECHNICAL = false;
			}
			
			else if(tuple.toLowerCase().startsWith("administrator:"))
			{
				this.store_mode_ADMINISTRATOR = true;
				
				this.store_mode_DATA_VALIDATION = false;
				this.store_mode_DOMAIN_NAME = false;
				this.store_mode_NAME_SERVERS = false;
				this.store_mode_REGISTRANT = false;
				this.store_mode_REGISTRANT_ADDRESS = false;
				this.store_mode_REGISTRANT_TYPE = false;
				this.store_mode_REGISTRAR = false;
				this.store_mode_REGISTRATION_STATUS = false;
				this.store_mode_RELEVANT_DATES = false;
				this.store_mode_TECHNICAL = false;
			}
			
			else if(tuple.toLowerCase().startsWith("name:"))
			{
				value = tuple.substring(5).trim();
				
				if(value.equals(""))
					return false;
				
				if(this.store_mode_ADMINISTRATOR && (admin_name == null || admin_name.trim().equals("")))
					this.admin_name = value;
				else if(this.store_mode_TECHNICAL && (tech_name == null || tech_name.trim().equals("")))
					this.tech_name = value;
				else if(this.store_mode_REGISTRANT && (registrant_name == null || registrant_name.trim().equals("")))
					this.registrant_name = value;
			}
			
						
			else if(tuple.toLowerCase().startsWith("organisation:") || tuple.toLowerCase().startsWith("organization:"))
			{
				value = tuple.substring(13).trim();
				
				if(value.equals(""))
					return false;
				
				if(this.store_mode_ADMINISTRATOR && (admin_organization == null || admin_organization.trim().equals("")))
					this.admin_organization = value;
				else if(this.store_mode_TECHNICAL && (tech_organization == null || tech_organization.trim().equals("")))
					this.tech_organization = value;
				else if(this.store_mode_REGISTRANT && (registrant_organization == null || registrant_organization.trim().equals("")))
					this.registrant_organization = value;
			}
			
			else if(tuple.toLowerCase().startsWith("language:"))
			{
				value = tuple.substring(9).trim();
				
				if(value.equals(""))
					return false;
				
				if(this.store_mode_ADMINISTRATOR && (admin_language == null || admin_language.trim().equals("")))
					this.admin_language = value;
				else if(this.store_mode_TECHNICAL && (tech_language == null || tech_language.trim().equals("")))
					this.tech_language = value;
				else if(this.store_mode_REGISTRANT && (registrant_language == null || registrant_language.trim().equals("")))
					this.registrant_language = value;
			}
			
			else if(tuple.toLowerCase().startsWith("phone:"))
			{
				value = tuple.substring(6).trim();
				
				if(value.equals(""))
					return false;
				
				if(this.store_mode_ADMINISTRATOR && (admin_phone == null || admin_phone.trim().equals("")))
					this.admin_phone = value;
				else if(this.store_mode_TECHNICAL && (tech_phone == null || tech_phone.trim().equals("")))
					this.tech_phone = value;
				else if(this.store_mode_REGISTRANT && (registrant_phone == null || registrant_phone.trim().equals("")))
					this.registrant_phone = value;
			}
			
			else if(tuple.toLowerCase().startsWith("fax-no:"))
			{
				value = tuple.substring(7).trim();
				
				if(value.equals(""))
					return false;
				
				if(this.store_mode_ADMINISTRATOR && (admin_fax == null || admin_fax.trim().equals("")))
					this.admin_fax = value;	
				else if(this.store_mode_TECHNICAL && (tech_fax == null || tech_fax.trim().equals("")))
					this.tech_fax = value;	
				else if(this.store_mode_REGISTRANT && (registrant_fax == null || registrant_fax.trim().equals("")))
					this.registrant_fax = value;								
			}
			
			else if(tuple.toLowerCase().startsWith("fax:"))
			{
				value = tuple.substring(4).trim();
				
				if(value.equals(""))
					return false;
				
				if(this.store_mode_ADMINISTRATOR && (admin_fax == null || admin_fax.trim().equals("")))
					this.admin_fax = value;
				else if(this.store_mode_TECHNICAL && (tech_fax == null || tech_fax.trim().equals("")))
					this.tech_fax = value;
				else if(this.store_mode_REGISTRANT && (registrant_fax == null || registrant_fax.trim().equals("")))
					this.registrant_fax = value;
			}
			
			
			
			else if(tuple.toLowerCase().startsWith("email:"))
			{
				value = tuple.substring(6).trim();
				
				if(value.equals(""))
					return false;
				
				if(this.store_mode_ADMINISTRATOR && (admin_email == null || admin_email.trim().equals("")))
					this.admin_email = value;
				else if(this.store_mode_TECHNICAL && (tech_email == null || tech_email.trim().equals("")))
					this.tech_email = value;
				else if(this.store_mode_REGISTRANT && (registrant_email == null || registrant_email.trim().equals("")))
					this.registrant_email = value;
			}
			
			else if(tuple.toLowerCase().startsWith("e-mail:"))
			{
				value = tuple.substring(7).trim();
				
				if(value.equals(""))
					return false;
				
				if(this.store_mode_ADMINISTRATOR && (admin_email == null || admin_email.trim().equals("")))
					this.admin_email = value;
				else if(this.store_mode_TECHNICAL && (tech_email == null || tech_email.trim().equals("")))
					this.tech_email = value;
				else if(this.store_mode_REGISTRANT && (registrant_email == null || registrant_email.trim().equals("")))
					this.registrant_email = value;
			}
			
			else if(tuple.toLowerCase().startsWith("website:"))
			{
				value = tuple.substring(5).trim();
				
				if(value.equals(""))
					return false;
				
				if(this.store_mode_ADMINISTRATOR && (admin_url == null || admin_url.trim().equals("")))
					this.admin_url = value;
				else if(this.store_mode_TECHNICAL && (tech_url == null || tech_url.trim().equals("")))
					this.tech_url = value;
				else if(this.store_mode_REGISTRANT && (registrant_url == null || registrant_url.trim().equals("")))
					this.registrant_url = value;
				else if(store_mode_REGISTRAR && (registrar_url == null || registrar_url.trim().equals("")))
					this.registrar_url = value;
			}
			
			else if(tuple.toLowerCase().startsWith("address:"))
			{
				value = tuple.substring(8).trim();
				
				if(value.equals(""))
					return false;
				
				if(this.store_mode_ADMINISTRATOR)
				{
					if(admin_street == null) 
						this.admin_street = value;
					else if(!this.admin_street.contains(value))
						admin_street = admin_street.trim() + " " + value;
				}
				
				else if(this.store_mode_TECHNICAL)
				{
					if(tech_street == null) 
						this.tech_street = value;
					else if(!this.tech_street.contains(value))
						tech_street = tech_street.trim() + " " + value;
				}
				
				else if(this.store_mode_REGISTRANT)
				{
					if(registrant_street == null) 
						this.registrant_street = value;
					else if(!this.registrant_street.contains(value))
						registrant_street = registrant_street.trim() + " " + value;
				}
			}
			
			else if(tuple.toLowerCase().startsWith("country:"))
			{
				value = tuple.substring(8).trim();
				
				if(value.equals(""))
					return false;
				
				if(this.store_mode_ADMINISTRATOR && (admin_country == null || admin_country.trim().equals("")))
					this.admin_country = value;	
				else if(this.store_mode_TECHNICAL && (tech_country == null || tech_country.trim().equals("")))
					this.tech_country = value;	
				else if(this.store_mode_REGISTRANT && (registrant_country == null || registrant_country.trim().equals("")))
					this.registrant_country = value;								
			}
			
			else if(tuple.toLowerCase().startsWith("anonymous:"))
			{
				value = tuple.substring(10).trim();
				
				if(value.equals(""))
					return false;
				
				if(this.store_mode_ADMINISTRATOR && (admin_anonymous == null || admin_anonymous.trim().equals("")))
					this.admin_anonymous = value;	
				else if(this.store_mode_TECHNICAL && (tech_anonymous == null || tech_anonymous.trim().equals("")))
					this.tech_anonymous = value;	
				else if(this.store_mode_REGISTRANT && (registrant_anonymous == null || registrant_anonymous.trim().equals("")))
					this.registrant_anonymous = value;								
			}
			
			else if(tuple.toLowerCase().startsWith("registered:"))
			{
				value = tuple.substring(11).trim();
				
				if(value.equals(""))
					return false;
				
				if(this.store_mode_ADMINISTRATOR && (admin_registered == null || admin_registered.trim().equals("")))
					this.admin_registered = value;	
				else if(this.store_mode_TECHNICAL && (tech_registered == null || tech_registered.trim().equals("")))
					this.tech_registered = value;	
				else if(this.store_mode_REGISTRANT && (registrant_registered == null || registrant_registered.trim().equals("")))
					this.registrant_registered = value;								
			}
			
			else if(tuple.toLowerCase().startsWith("changed:"))
			{
				value = tuple.substring(8).trim();
				
				if(value.equals(""))
					return false;
				
				if(this.store_mode_ADMINISTRATOR && (admin_changed == null || admin_changed.trim().equals("")))
					this.admin_changed = value;	
				else if(this.store_mode_TECHNICAL && (tech_changed == null || tech_changed.trim().equals("")))
					this.tech_changed = value;	
				else if(this.store_mode_REGISTRANT && (registrant_changed == null || registrant_changed.trim().equals("")))
					this.registrant_changed = value;								
			}
			
			else if(tuple.toLowerCase().startsWith("obsoleted:"))
			{
				value = tuple.substring(10).trim();
				
				if(value.equals(""))
					return false;
				
				if(this.store_mode_ADMINISTRATOR && (admin_obsoleted == null || admin_obsoleted.trim().equals("")))
					this.admin_obsoleted = value;	
				else if(this.store_mode_TECHNICAL && (tech_obsoleted == null || tech_obsoleted.trim().equals("")))
					this.tech_obsoleted = value;	
				else if(this.store_mode_REGISTRANT && (registrant_obsoleted == null || registrant_obsoleted.trim().equals("")))
					this.registrant_obsoleted = value;								
			}
			
			else if(tuple.toLowerCase().startsWith("contact:"))
			{
				value = tuple.substring(8).trim();
				
				if(value.equals(""))
					return false;
				
				if(this.store_mode_ADMINISTRATOR && (admin_name == null || admin_name.trim().equals("")))
					this.admin_name = value;	
				else if(this.store_mode_TECHNICAL && (tech_name == null || tech_name.trim().equals("")))
					this.tech_name = value;	
				else if(this.store_mode_REGISTRANT && (registrant_name == null || registrant_name.trim().equals("")))
					this.registrant_name = value;								
			}
			
			else if(tuple.toLowerCase().startsWith("nic-hdl:"))
			{
				value = tuple.substring(8).trim();
				
				if(value.equals(""))
					return false;
				
					if(nic_hdl == null)
						nic_hdl = value;
					else if(!nic_hdl.contains(value))
						nic_hdl = nic_hdl + ", " + value;											
			}
			
			else if(tuple.toLowerCase().startsWith("registrant type:"))
			{
				this.registrant_type = tuple.substring(16).trim();
				
				store_mode_REGISTRANT_TYPE = true;
				
				this.store_mode_ADMINISTRATOR = false;
				this.store_mode_DATA_VALIDATION = false;
				this.store_mode_DOMAIN_NAME = false;
				this.store_mode_NAME_SERVERS = false;
				this.store_mode_REGISTRANT = false;
				this.store_mode_REGISTRANT_ADDRESS = false;

				this.store_mode_REGISTRAR = false;
				this.store_mode_REGISTRATION_STATUS = false;
				this.store_mode_RELEVANT_DATES = false;
				this.store_mode_TECHNICAL = false;
			}
			
			else if(tuple.toLowerCase().startsWith("registrant's address:"))
			{
				if(this.registrant_street == null)
					this.registrant_street = tuple.substring(21).trim();
				else if(!registrant_street.contains(tuple))
					this.registrant_street = this.registrant_street.trim() + " " + tuple.substring(21).trim(); 
				
				store_mode_REGISTRANT_ADDRESS = true;
				
				this.store_mode_ADMINISTRATOR = false;
				this.store_mode_DATA_VALIDATION = false;
				this.store_mode_DOMAIN_NAME = false;
				this.store_mode_NAME_SERVERS = false;
				this.store_mode_REGISTRANT = false;

				this.store_mode_REGISTRANT_TYPE = false;
				this.store_mode_REGISTRAR = false;
				this.store_mode_REGISTRATION_STATUS = false;
				this.store_mode_RELEVANT_DATES = false;
				this.store_mode_TECHNICAL = false;
			}
			
			else if(tuple.toLowerCase().startsWith("registrant address:"))
			{
				if(this.registrant_street == null)
					this.registrant_street = tuple.substring(19).trim();
				else if(!registrant_street.contains(tuple))
					this.registrant_street = this.registrant_street.trim() + " " + tuple.substring(19).trim(); 
				
				store_mode_REGISTRANT_ADDRESS = true;
				
				this.store_mode_ADMINISTRATOR = false;
				this.store_mode_DATA_VALIDATION = false;
				this.store_mode_DOMAIN_NAME = false;
				this.store_mode_NAME_SERVERS = false;
				this.store_mode_REGISTRANT = false;

				this.store_mode_REGISTRANT_TYPE = false;
				this.store_mode_REGISTRAR = false;
				this.store_mode_REGISTRATION_STATUS = false;
				this.store_mode_RELEVANT_DATES = false;
				this.store_mode_TECHNICAL = false;
			}
			
			else if(tuple.toLowerCase().startsWith("data validation:"))
			{
				this.data_validation = tuple.substring(16).trim();
				
				store_mode_DATA_VALIDATION = true;
				
				this.store_mode_ADMINISTRATOR = false;
				this.store_mode_DOMAIN_NAME = false;
				this.store_mode_NAME_SERVERS = false;
				this.store_mode_REGISTRANT = false;
				this.store_mode_REGISTRANT_ADDRESS = false;
				this.store_mode_REGISTRANT_TYPE = false;
				this.store_mode_REGISTRAR = false;
				this.store_mode_REGISTRATION_STATUS = false;
				this.store_mode_RELEVANT_DATES = false;
				this.store_mode_TECHNICAL = false;
			}
			
			else if(tuple.toLowerCase().startsWith("registrant organization:"))
				this.registrant_organization = tuple.substring(24).trim();
									
			else if(tuple.toLowerCase().startsWith("org:"))
				this.registrant_organization = tuple.substring(4).trim();
			
			else if(tuple.toLowerCase().contains("company number:"))
				this.registrant_organization = tuple.trim();
			
			else if(tuple.toLowerCase().startsWith("registrant street:"))
				this.registrant_street = tuple.substring(18).trim();
			
			else if(tuple.toLowerCase().startsWith("registrant's address:"))
				this.registrant_street = tuple.substring(21).trim();
			
			else if(tuple.toLowerCase().startsWith("registrant street1:"))
				this.registrant_street = tuple.substring(19).trim();
			
			else if(tuple.toLowerCase().startsWith("registrant street2:"))
			{
				if(registrant_street.contains(tuple.substring(19).trim()))
					this.registrant_street = registrant_street + " " + tuple.substring(19).trim();
			}
				
			
			else if(tuple.toLowerCase().startsWith("registrant street3:"))
			{
				if(!registrant_street.contains(tuple.substring(19).trim()))
					this.registrant_street = registrant_street + " " + tuple.substring(19).trim();	
			}
				
			
			else if(tuple.toLowerCase().startsWith("registrant city:"))
				this.registrant_city = tuple.substring(16).trim();
			
			else if(tuple.toLowerCase().startsWith("registrant state province:"))
				this.registrant_state_province = tuple.substring(26).trim();
			
			else if(tuple.toLowerCase().startsWith("registrant state/province:"))
				this.registrant_state_province = tuple.substring(26).trim();
			
			else if(tuple.toLowerCase().startsWith("registrant province/state:"))
				this.registrant_state_province = tuple.substring(26).trim();
			
			else if(tuple.toLowerCase().startsWith("registrant postalcode:"))
				this.registrant_postal_code = tuple.substring(22).trim();
			
			else if(tuple.toLowerCase().startsWith("registrant postal code:"))
				this.registrant_postal_code = tuple.substring(23).trim();
			
			else if(tuple.toLowerCase().startsWith("registrant country:"))
				this.registrant_country = tuple.substring(19).trim();
			
			else if(tuple.toLowerCase().startsWith("registrant phone:"))
				this.registrant_phone = tuple.substring(17).trim();
			
			else if(tuple.toLowerCase().startsWith("registrant phone :"))
				this.registrant_phone = tuple.substring(18).trim();
			
			else if(tuple.toLowerCase().startsWith("registrant phone ext:"))
				this.registrant_phone_ext = tuple.substring(21).trim();
			
			else if(tuple.toLowerCase().startsWith("registrant phone ext.:"))
				this.registrant_phone_ext = tuple.substring(22).trim();
			
			else if(tuple.toLowerCase().startsWith("registrant fax:"))
				this.registrant_fax = tuple.substring(15).trim();
			
			else if(tuple.toLowerCase().startsWith("registrant fax ext:"))
				this.registrant_fax_ext = tuple.substring(19).trim();
			
			else if(tuple.toLowerCase().startsWith("registrant fax ext.:"))
				this.registrant_fax_ext = tuple.substring(20).trim();
			
			else if(tuple.toLowerCase().startsWith("registrant email:"))
			{
				this.registrant_email = tuple.substring(17).trim();
				
				try
				{
					if(registrant_email.contains("@"))
					{
						registrant_email_domain_name = registrant_email.substring(registrant_email.lastIndexOf("@")+1);												
					}
				}
				catch(Exception ee){}
			}
			
			else if(tuple.toLowerCase().startsWith("registry admin id:"))
				this.registry_admin_id = tuple.substring(18).trim();
			
			else if(tuple.toLowerCase().startsWith("admin id:"))
				this.registry_admin_id = tuple.substring(9).trim();
			
			else if(tuple.toLowerCase().startsWith("admin name:"))
				this.admin_name = tuple.substring(11).trim();
			
			else if(tuple.toLowerCase().startsWith("admin organization:"))
				this.admin_organization = tuple.substring(19).trim();
			
			else if(tuple.toLowerCase().startsWith("admin street:"))
				this.admin_street = tuple.substring(13).trim();
			
			else if(tuple.toLowerCase().startsWith("admin street1:"))
				this.admin_street = tuple.substring(14).trim();
			
			else if(tuple.toLowerCase().startsWith("admin street2:"))
				this.admin_street = admin_street + " " + tuple.substring(14).trim();
			
			else if(tuple.toLowerCase().startsWith("admin street3:"))
				this.admin_street = admin_street + " " + tuple.substring(14).trim();
			
			else if(tuple.toLowerCase().startsWith("admin city:"))
				this.admin_city = tuple.substring(11).trim();
			
			else if(tuple.toLowerCase().startsWith("admin state province:"))
				this.admin_state_province = tuple.substring(21).trim();
			
			else if(tuple.toLowerCase().startsWith("admin state/province:"))
				this.admin_state_province = tuple.substring(21).trim();
			
			else if(tuple.toLowerCase().startsWith("admin province/state:"))
				this.admin_state_province = tuple.substring(21).trim();
			
			else if(tuple.toLowerCase().startsWith("admin postal code:"))
				this.admin_postal_code = tuple.substring(18).trim();
			
			else if(tuple.toLowerCase().startsWith("admin postalcode:"))
				this.admin_postal_code = tuple.substring(17).trim();
			
			else if(tuple.toLowerCase().startsWith("admin country:"))
				this.admin_country = tuple.substring(14).trim();
			
			else if(tuple.toLowerCase().startsWith("admin phone:"))
				this.admin_phone = tuple.substring(12).trim();
			
			else if(tuple.toLowerCase().startsWith("admin phone :"))
				this.admin_phone = tuple.substring(13).trim();
			
			else if(tuple.toLowerCase().startsWith("admin phone ext:"))
				this.admin_phone_ext = tuple.substring(16).trim();
			
			else if(tuple.toLowerCase().startsWith("admin phone ext.:"))
				this.admin_phone_ext = tuple.substring(17).trim();
			
			else if(tuple.toLowerCase().startsWith("admin fax:"))
				this.admin_fax = tuple.substring(10).trim();
			
			else if(tuple.toLowerCase().startsWith("admin fax ext:"))
				this.admin_fax_ext = tuple.substring(14).trim();
			
			else if(tuple.toLowerCase().startsWith("admin fax ext.:"))
				this.admin_fax_ext = tuple.substring(15).trim();
			
			else if(tuple.toLowerCase().startsWith("admin email:"))
			{
				this.admin_email = tuple.substring(12).trim();
				
				try
				{
					if(admin_email.contains("@"))
					{
						admin_email_domain_name = admin_email.substring(admin_email.lastIndexOf("@")+1);												
					}
				}
				catch(Exception ee){}
			}
			
			else if(tuple.toLowerCase().startsWith("registry tech id:"))
				this.registry_tech_id = tuple.substring(17).trim();
			
			else if(tuple.toLowerCase().startsWith("tech id:"))
				this.registry_tech_id = tuple.substring(8).trim();
			
			else if(tuple.toLowerCase().startsWith("tech name:"))
				this.tech_name = tuple.substring(10).trim();
			
			else if(tuple.toLowerCase().startsWith("tech organization:"))
				this.tech_organization = tuple.substring(18).trim();
			
			else if(tuple.toLowerCase().startsWith("tech street:"))
				this.tech_street = tuple.substring(12).trim();
			
			else if(tuple.toLowerCase().startsWith("tech street1:"))
				this.tech_street = tuple.substring(13).trim();
			
			else if(tuple.toLowerCase().startsWith("tech street2:"))
				this.tech_street = tech_street + " " + tuple.substring(13).trim();
			
			else if(tuple.toLowerCase().startsWith("tech street3:"))
				this.tech_street = tech_street + " " + tuple.substring(13).trim();
			
			else if(tuple.toLowerCase().startsWith("tech city:"))
				this.tech_city = tuple.substring(10).trim();
			
			else if(tuple.toLowerCase().startsWith("tech state province:"))
				this.tech_state_province = tuple.substring(20).trim();
			
			else if(tuple.toLowerCase().startsWith("tech province/state:"))
				this.tech_state_province = tuple.substring(20).trim();
			
			else if(tuple.toLowerCase().startsWith("tech state/province:"))
				this.tech_state_province = tuple.substring(20).trim();
			
			else if(tuple.toLowerCase().startsWith("tech postal code:"))
				this.tech_postal_code = tuple.substring(17).trim();
			
			else if(tuple.toLowerCase().startsWith("tech postalcode:"))
				this.tech_postal_code = tuple.substring(16).trim();
			
			else if(tuple.toLowerCase().startsWith("tech country:"))
				this.tech_country = tuple.substring(13).trim();
			
			else if(tuple.toLowerCase().startsWith("tech phone:"))
				this.tech_phone = tuple.substring(11).trim();
			
			else if(tuple.toLowerCase().startsWith("tech phone :"))
				this.tech_phone = tuple.substring(12).trim();
			
			else if(tuple.toLowerCase().startsWith("tech phone ext:"))
				this.tech_phone_ext = tuple.substring(15).trim();
			
			else if(tuple.toLowerCase().startsWith("tech phone ext.:"))
				this.tech_phone_ext = tuple.substring(16).trim();
			
			else if(tuple.toLowerCase().startsWith("tech fax:"))
				this.tech_fax = tuple.substring(9).trim();
			
			else if(tuple.toLowerCase().startsWith("tech fax ext:"))
				this.tech_fax_ext = tuple.substring(13).trim();
			
			else if(tuple.toLowerCase().startsWith("tech fax ext.:"))
				this.tech_fax_ext = tuple.substring(14).trim();
			
			else if(tuple.toLowerCase().startsWith("tech email:"))
			{
				this.tech_email = tuple.substring(11).trim();
				
				try
				{
					if(tech_email.contains("@"))
					{
						tech_email_domain_name = tech_email.substring(tech_email.lastIndexOf("@")+1);												
					}
				}
				catch(Exception ee){}
			}
			
			else if(tuple.toLowerCase().startsWith("registry billing id:"))
				this.billing_id = tuple.substring(20).trim();
			
			else if(tuple.toLowerCase().startsWith("billing id:"))
				this.billing_id = tuple.substring(11).trim();
			
			else if(tuple.toLowerCase().startsWith("billing name:"))
				this.billing_name = tuple.substring(13).trim();
			
			else if(tuple.toLowerCase().startsWith("billing organization:"))
				this.billing_organization = tuple.substring(21).trim();
			
			else if(tuple.toLowerCase().startsWith("billing street:"))
				this.billing_street = tuple.substring(15).trim();
			
			else if(tuple.toLowerCase().startsWith("billing city:"))
				this.billing_city = tuple.substring(13).trim();
			
			//else if(tuple.toLowerCase().startsWith("billing email:"))
			//	this.billing_email = tuple.substring(14).trim();
			
			else if(tuple.toLowerCase().startsWith("billing email:"))
			{
				this.billing_email = tuple.substring(14).trim();
				
				try
				{
					if(admin_email.contains("@"))
					{
						billing_email_domain_name = billing_email.substring(billing_email.lastIndexOf("@")+1);												
					}
				}
				catch(Exception ee){}
			}
			
			else if(tuple.toLowerCase().startsWith("domain idn name:"))
				this.domain_idn_name = tuple.substring(16).trim();
			
			else if(tuple.toLowerCase().startsWith("billing state province:"))
				this.billing_state_province = tuple.substring(23).trim();
			
			else if(tuple.toLowerCase().startsWith("billing state province:"))
				this.billing_state_province = tuple.substring(23).trim();
			
			else if(tuple.toLowerCase().startsWith("billing state/province:"))
				this.billing_state_province = tuple.substring(23).trim();
			
			else if(tuple.toLowerCase().startsWith("billing province/state:"))
				this.billing_state_province = tuple.substring(23).trim();
			
			else if(tuple.toLowerCase().startsWith("billing postal code:"))
				this.billing_postal_code = tuple.substring(20).trim();
			
			else if(tuple.toLowerCase().startsWith("billing country:"))
				this.billing_country = tuple.substring(16).trim();
			
			else if(tuple.toLowerCase().startsWith("billing phone:"))
				this.billing_phone = tuple.substring(14).trim();
			
			else if(tuple.toLowerCase().startsWith("billing phone :"))
				this.billing_phone = tuple.substring(15).trim();
			
			else if(tuple.toLowerCase().startsWith("billing phone ext:"))
				this.billing_phone_ext = tuple.substring(18).trim();
			
			else if(tuple.toLowerCase().startsWith("billing fax:"))
				this.billing_fax = tuple.substring(12).trim();
			
			else if(tuple.toLowerCase().startsWith("billing fax ext:"))
				this.billing_fax_ext = tuple.substring(16).trim();
			
			else if(tuple.toLowerCase().startsWith("billing_id:"))
				this.billing_id = tuple.substring(11).trim();
			
			else if(tuple.toLowerCase().startsWith("billing organization:"))
				this.billing_organization = tuple.substring(21).trim();
			
			else if(tuple.toLowerCase().startsWith("billing street:"))
				this.billing_street = tuple.substring(15).trim();
			
			else if(tuple.toLowerCase().startsWith("billing city:"))
				this.billing_city = tuple.substring(13).trim();
			
			else if(tuple.toLowerCase().startsWith("billing state_province:"))
				this.billing_state_province = tuple.substring(23).trim();
			
			else if(tuple.toLowerCase().startsWith("billing state province:"))
				this.billing_state_province = tuple.substring(23).trim();
			
			else if(tuple.toLowerCase().startsWith("billing state/province:"))
				this.billing_state_province = tuple.substring(23).trim();
			
			else if(tuple.toLowerCase().startsWith("billing postal code:"))
				this.billing_postal_code = tuple.substring(20).trim();
			
			else if(tuple.toLowerCase().startsWith("billing country:"))
				this.billing_country = tuple.substring(16).trim();
			
			else if(tuple.toLowerCase().startsWith("billing phone:"))
				this.billing_phone = tuple.substring(14).trim();
			
			else if(tuple.toLowerCase().startsWith("billing phone ext:"))
				this.billing_phone_ext = tuple.substring(18).trim();
			
			else if(tuple.toLowerCase().startsWith("billing fax:"))
				this.billing_fax = tuple.substring(12).trim();
			
			else if(tuple.toLowerCase().startsWith("billing fax ext:"))
				this.billing_fax_ext = tuple.substring(16).trim();
			
			else if(tuple.toLowerCase().startsWith("registry_billing_id:"))
				this.billing_id = tuple.substring(20).trim();
			
			else if(tuple.toLowerCase().startsWith("billing_id:"))
				this.billing_id = tuple.substring(11).trim();
			
			else if(tuple.toLowerCase().startsWith("billing_name:"))
				this.billing_name = tuple.substring(13).trim();
			
			else if(tuple.toLowerCase().startsWith("billing_organization:"))
				this.billing_organization = tuple.substring(21).trim();
			
			else if(tuple.toLowerCase().startsWith("billing_street:"))
				this.billing_street = tuple.substring(15).trim();
			
			else if(tuple.toLowerCase().startsWith("billing_city:"))
				this.billing_city = tuple.substring(13).trim();
			
			else if(tuple.toLowerCase().startsWith("billing_email:"))
				this.billing_email = tuple.substring(14).trim();
			
			else if(tuple.toLowerCase().startsWith("billing_state_province:"))
				this.billing_state_province = tuple.substring(23).trim();
			
			else if(tuple.toLowerCase().startsWith("billing_state_province:"))
				this.billing_state_province = tuple.substring(23).trim();
			
			else if(tuple.toLowerCase().startsWith("billing_state/province:"))
				this.billing_state_province = tuple.substring(23).trim();
			
			else if(tuple.toLowerCase().startsWith("billing_postal_code:"))
				this.billing_postal_code = tuple.substring(20).trim();
			
			else if(tuple.toLowerCase().startsWith("billing_country:"))
				this.billing_country = tuple.substring(16).trim();
			
			else if(tuple.toLowerCase().startsWith("billing_phone:"))
				this.billing_phone = tuple.substring(14).trim();
			
			else if(tuple.toLowerCase().startsWith("billing_phone_ext:"))
				this.billing_phone_ext = tuple.substring(18).trim();
			
			else if(tuple.toLowerCase().startsWith("billing_fax:"))
				this.billing_fax = tuple.substring(12).trim();
			
			else if(tuple.toLowerCase().startsWith("billing_fax_ext:"))
				this.billing_fax_ext = tuple.substring(16).trim();
			
			else if(tuple.toLowerCase().startsWith("billing_id:"))
				this.billing_id = tuple.substring(11).trim();
			
			else if(tuple.toLowerCase().startsWith("billing_organization:"))
				this.billing_organization = tuple.substring(21).trim();
			
			else if(tuple.toLowerCase().startsWith("billing_street:"))
				this.billing_street = tuple.substring(15).trim();
			
			else if(tuple.toLowerCase().startsWith("billing_city:"))
				this.billing_city = tuple.substring(13).trim();
			
			else if(tuple.toLowerCase().startsWith("billing_state_province:"))
				this.billing_state_province = tuple.substring(23).trim();
			
			else if(tuple.toLowerCase().startsWith("billing_state/province:"))
				this.billing_state_province = tuple.substring(23).trim();
			
			else if(tuple.toLowerCase().startsWith("billing_postal_code:"))
				this.billing_postal_code = tuple.substring(20).trim();
			
			else if(tuple.toLowerCase().startsWith("billing_country:"))
				this.billing_country = tuple.substring(16).trim();
			
			else if(tuple.toLowerCase().startsWith("billing_phone:"))
				this.billing_phone = tuple.substring(14).trim();
			
			else if(tuple.toLowerCase().startsWith("billing_phone_ext:"))
				this.billing_phone_ext = tuple.substring(18).trim();
			
			else if(tuple.toLowerCase().startsWith("billing_fax:"))
				this.billing_fax = tuple.substring(12).trim();
			
			else if(tuple.toLowerCase().startsWith("billing_fax_ext:"))
				this.billing_fax_ext = tuple.substring(16).trim();
			
			else if(tuple.toLowerCase().startsWith("first lookup date:"))
				this.first_lookup_date = tuple.substring(18).trim();
			
			else if(tuple.toLowerCase().startsWith("last lookup date:"))
				this.last_lookup_date = tuple.substring(17).trim();
			
			else if(tuple.toLowerCase().startsWith("tld:"))
				this.TLD = tuple.substring(4).trim();
			
			else if(tuple.toLowerCase().startsWith("sponsoring registrar address:"))
				this.sponsoring_registrar_address = tuple.substring(29).trim();
			
			else if(tuple.toLowerCase().startsWith("sponsoring registrar country:"))
				this.sponsoring_registrar_country = tuple.substring(29).trim();
			
			else if(tuple.toLowerCase().startsWith("sponsoring registrar phone:"))
				this.sponsoring_registrar_phone = tuple.substring(27).trim();
			
			else if(tuple.toLowerCase().startsWith("sponsoring registrar contact:"))
				this.sponsoring_registrar_contact = tuple.substring(29).trim();
			
			else if(tuple.toLowerCase().startsWith("reseller email:"))
				this.reseller_email = tuple.substring(15).trim();
			
			else if(tuple.toLowerCase().startsWith("reseller url:"))
				this.reseller_url = tuple.substring(13).trim();
			
			else if(tuple.toLowerCase().startsWith("sponsoring registrar email:"))
			{
				this.sponsoring_registrar_email = tuple.substring(27).trim();
				
				try
				{
					if(sponsoring_registrar_email.contains("@"))
					{
						sponsoring_registrar_email_domain_name = sponsoring_registrar_email.substring(sponsoring_registrar_email.lastIndexOf("@")+1);												
					}
				}
				catch(Exception ee){}
			}
			
			else if(tuple.toLowerCase().startsWith("sponsoring registrar admin email:"))
			{
				this.sponsoring_registrar_admin_email = tuple.substring(33).trim();
				
				try
				{
					if(sponsoring_registrar_admin_email.contains("@"))
					{
						sponsoring_registrar_admin_email_domain_name = sponsoring_registrar_admin_email.substring(sponsoring_registrar_admin_email.lastIndexOf("@")+1);												
					}
				}
				catch(Exception ee){}
			}


			else if(tuple.toLowerCase().startsWith("sponsoring registrar customer service contact:"))
				this.sponsoring_registrar_customer_service_contact = tuple.substring(46).trim();
			
			else if(tuple.toLowerCase().startsWith("sponsoring registrar customer service email:"))
			{
				this.sponsoring_registrar_customer_service_email = tuple.substring(44).trim();
				
				try
				{
					if(sponsoring_registrar_customer_service_email.contains("@"))
					{
						sponsoring_registrar_customer_service_email_domain_name = sponsoring_registrar_customer_service_email.substring(sponsoring_registrar_customer_service_email.lastIndexOf("@")+1);												
					}
				}
				catch(Exception ee){}
			}
			
			else if(tuple.toLowerCase().startsWith("sponsoring registrar admin contact:"))
				this.sponsoring_registrar_admin_contact = tuple.substring(35).trim();
			
			//description
			
			/*else if(tuple.toLowerCase().startsWith(":"))
				this. = tuple.substring().trim();
			
			else if(tuple.toLowerCase().startsWith(":"))
				this. = tuple.substring().trim();
			
			else if(tuple.toLowerCase().startsWith(":"))
				this. = tuple.substring().trim();
			
			else if(tuple.toLowerCase().startsWith(":"))
				this. = tuple.substring().trim();
			
			else if(tuple.toLowerCase().startsWith(":"))
				this. = tuple.substring().trim();
			
			else if(tuple.toLowerCase().startsWith(":"))
				this. = tuple.substring().trim();
			
			else if(tuple.toLowerCase().startsWith(":"))
				this. = tuple.substring().trim();
			
			else if(tuple.toLowerCase().startsWith(":"))
				this. = tuple.substring().trim();
			
			else if(tuple.toLowerCase().startsWith(":"))
				this. = tuple.substring().trim();
			
			else if(tuple.toLowerCase().startsWith(":"))
				this. = tuple.substring().trim();
			
			else if(tuple.toLowerCase().startsWith(":"))
				this. = tuple.substring().trim();
			
			else if(tuple.toLowerCase().startsWith(":"))
				this. = tuple.substring().trim();
			
			else if(tuple.toLowerCase().startsWith(":"))
				this. = tuple.substring().trim();*/
			
			
			
			else if(tuple.toLowerCase().startsWith("tld registrar server:"))
			{
				this.TLD_WHOIS_REGISTRAR = tuple.substring(21).trim();
				this.TLD_WHOIS_REGISTRAR_FULL_LINE = tuple.substring(21).trim();
			}
			
			else if(tuple.toLowerCase().startsWith("nslookup_request:"))
			{
				if(this.node_nslookup == null)
					node_nslookup = new Node_Nslookup();
								
				node_nslookup.request = tuple.substring(17);
			}
			
			
			else if(tuple.toLowerCase().startsWith("nslookup_server:"))
			{
				if(this.node_nslookup == null)
					node_nslookup = new Node_Nslookup();
								
				node_nslookup.server = tuple.substring(16);
			}
			
			else if(tuple.toLowerCase().startsWith("nslookup_address_1:"))
			{
				if(this.node_nslookup == null)
					node_nslookup = new Node_Nslookup();
								
				node_nslookup.address_1 = tuple.substring(19);
			}
			
			else if(tuple.toLowerCase().startsWith("nslookup_name:"))
			{
				if(this.node_nslookup == null)
					node_nslookup = new Node_Nslookup();
								
				node_nslookup.name = tuple.substring(14);
			}
			
			else if(tuple.toLowerCase().startsWith("nslookup_address_2:"))
			{
				if(this.node_nslookup == null)
					node_nslookup = new Node_Nslookup();
								
				node_nslookup.address_2 = tuple.substring(19);
			}
			
			else if(tuple.toLowerCase().startsWith("nslookup_ipv4_first:"))
			{
				if(this.node_nslookup == null)
					node_nslookup = new Node_Nslookup();
								
				node_nslookup.ipv4_first = tuple.substring(20);
			}
			
			else if(tuple.toLowerCase().startsWith("nslookup_ipv6_first:"))
			{
				if(this.node_nslookup == null)
					node_nslookup = new Node_Nslookup();
								
				node_nslookup.ipv6_first = tuple.substring(20);
			}
			
			else if(tuple.toLowerCase().startsWith("nslookup_ipv4:"))
			{
				if(this.node_nslookup == null)
					node_nslookup = new Node_Nslookup();
								
				node_nslookup.ipv4 = tuple.substring(14);
			}
			
			else if(tuple.toLowerCase().startsWith("nslookup_ipv6:"))
			{
				if(this.node_nslookup == null)
					node_nslookup = new Node_Nslookup();
								
				node_nslookup.ipv6 = tuple.substring(14);
			}
			
			else if(tuple.toLowerCase().startsWith("nslookup_last_retrieved:"))
			{
				if(this.node_nslookup == null)
					node_nslookup = new Node_Nslookup();
								
				node_nslookup.last_retrieved = tuple.substring(24);
			}
			
			else if(tuple.toLowerCase().startsWith("nslookup_last_update_time:"))
			{
				if(this.node_nslookup == null)
					node_nslookup = new Node_Nslookup();
								
				try	{	node_nslookup.last_update_time = Long.parseLong(tuple.substring(26).trim());}catch(Exception e){}
			}
			
			else if(tuple.toLowerCase().startsWith("nslookup_authoritative:"))
			{
				if(this.node_nslookup == null)
					node_nslookup = new Node_Nslookup();
								
				node_nslookup.authoritative = tuple.substring(23);
			}
			
			else if(tuple.toLowerCase().startsWith("nslookup_source:"))
			{
				if(this.node_nslookup == null)
					node_nslookup = new Node_Nslookup();
								
				//node_nslookup.SOURCE = tuple.substring(16);
			}
			
			
			else if(tuple.toLowerCase().startsWith("nslookup_authoritative:"))
			{
				if(this.node_nslookup == null)
					node_nslookup = new Node_Nslookup();
								
				node_nslookup.authoritative = tuple.substring(23);
			}
			
			else if(tuple.toLowerCase().startsWith("geolookup_request:"))
			{
				if(this.node_geo == null)
					node_geo = new Node_GeoIP();
								
				node_geo.request = tuple.substring(18);
			}
			
			else if(tuple.toLowerCase().startsWith("geolookup_ip:"))
			{
				if(this.node_geo == null)
					node_geo = new Node_GeoIP();
								
				node_geo.ip = tuple.substring(13);
			}
			
			else if(tuple.toLowerCase().startsWith("geolookup_country_code:"))
			{
				if(this.node_geo == null)
					node_geo = new Node_GeoIP();
								
				node_geo.country_code = tuple.substring(23);
			}
			
			else if(tuple.toLowerCase().startsWith("geolookup_country_name:"))
			{
				if(this.node_geo == null)
					node_geo = new Node_GeoIP();
								
				node_geo.country_name = tuple.substring(23);
			}
			
			else if(tuple.toLowerCase().startsWith("geolookup_region_code:"))
			{
				if(this.node_geo == null)
					node_geo = new Node_GeoIP();
								
				node_geo.country_code = tuple.substring(22);
			}
			
			else if(tuple.toLowerCase().startsWith("geolookup_region_name:"))
			{
				if(this.node_geo == null)
					node_geo = new Node_GeoIP();
								
				node_geo.region_state_name = tuple.substring(22);
			}
			
			else if(tuple.toLowerCase().startsWith("geolookup_city:"))
			{
				if(this.node_geo == null)
					node_geo = new Node_GeoIP();
								
				node_geo.city = tuple.substring(15);
			}
			
			else if(tuple.toLowerCase().startsWith("geolookup_zip_code:"))
			{
				if(this.node_geo == null)
					node_geo = new Node_GeoIP();
								
				node_geo.zip_code = tuple.substring(19);
			}
			
			else if(tuple.toLowerCase().startsWith("geolookup_time_zone:"))
			{
				if(this.node_geo == null)
					node_geo = new Node_GeoIP();
								
				node_geo.time_zone = tuple.substring(20);
			}
			
			else if(tuple.toLowerCase().startsWith("geolookup_latitude:"))
			{
				if(this.node_geo == null)
					node_geo = new Node_GeoIP();
								
				node_geo.latitude = tuple.substring(19);
				
				
				
				if(Node_GeoIP.jitter_lat_lon)
				{
					try	{	node_geo.lat = (Double.parseDouble(node_geo.latitude.trim()) + (Node_GeoIP.jitter_lat_value++ * 0.00001));	}	 catch(Exception e){}
				}
				else
				{
					try	{	node_geo.lat = Double.parseDouble(node_geo.latitude.trim());	}	 catch(Exception e){}
				}
				
			}
			
			else if(tuple.toLowerCase().startsWith("geolookup_longitude:"))
			{
				if(this.node_geo == null)
					node_geo = new Node_GeoIP();
								
				node_geo.longitude = tuple.substring(20);
				
				if(Node_GeoIP.jitter_lat_lon)
				{
					try	{	node_geo.lon = (Double.parseDouble(node_geo.longitude.trim()) + (Node_GeoIP.jitter_lon_value++ * 0.000001*Math.random()));	}	 catch(Exception e){}
				}
				else
				{
					try	{	node_geo.lon = Double.parseDouble(node_geo.longitude.trim());	}	 catch(Exception e){}
				}
			}
			
			else if(tuple.toLowerCase().startsWith("geolookup_metro_code:"))
			{
				if(this.node_geo == null)
					node_geo = new Node_GeoIP();
								
				node_geo.metro_area_code = tuple.substring(21);
			}
			
			else if(tuple.toLowerCase().startsWith("geolookup_last_retrieved:"))
			{
				if(this.node_geo == null)
					node_geo = new Node_GeoIP();
								
				node_geo.last_retrieved = tuple.substring(25);
			}
			
			else if(tuple.toLowerCase().startsWith("geolookup_last_updated:"))
			{
				if(this.node_geo == null)
					node_geo = new Node_GeoIP();
								
				node_geo.timeStamp = tuple.substring(23);
			}
			
			else if(tuple.toLowerCase().startsWith("geolookup_source:"))
			{
				if(this.node_geo == null)
					node_geo = new Node_GeoIP();
								
				//node_geo.SOURCE = tuple.substring(17);
			}
			
			else if(tuple.toLowerCase().startsWith("geolookup_authoritative:"))
			{
				if(this.node_geo == null)
					node_geo = new Node_GeoIP();
								
				node_geo.authoritative = tuple.substring(24);
			}
			
			//
			//DISMISS
			//
			else if(tuple.toLowerCase().startsWith("notice"))
				return false;
			
			else if(tuple.toLowerCase().startsWith("terms of use"))
				return false;
			
			else if(tuple.toLowerCase().startsWith("the data is for"))
				return false;
			
			else if(tuple.toLowerCase().startsWith("this data"))
				return false;
			
			else if(tuple.toLowerCase().startsWith("this information"))
				return false;
			
			else if(tuple.toLowerCase().startsWith("copyright"))
				return false;
			
			else if(tuple.toLowerCase().contains("url of the icann whois data problem"))
				return false;
			
			else if(tuple.toLowerCase().contains("only for lawful purposes and that,"))
				return false;
			
			else if(tuple.toLowerCase().startsWith("visit"))
				return false;
			
			else if(tuple.toLowerCase().startsWith("for more information"))
				return false;
			
			else if(tuple.toLowerCase().startsWith("by the following "))
				return false;
			
			else if(tuple.toLowerCase().startsWith("http"))
				return false;
			
			else if(tuple.toLowerCase().contains("url of the icann whois"))
				return false;
			
			else if(tuple.toLowerCase().contains("allow, enable, or otherwise support"))
				return false;
			
			else if(tuple.toLowerCase().contains("whois lookup made"))
				return false;
			
			else if(tuple.toLowerCase().contains("whois lookup"))
				return false;
			
			else if(tuple.toLowerCase().contains("this information and the"))
				return false;
			
			else if(tuple.toLowerCase().contains("this whois"))
				return false;
			
			else if(tuple.toLowerCase().contains("by the terms of"))
				return false;
			
			else if(tuple.toLowerCase().contains("which includes"))
				return false;
			
			else if(tuple.toLowerCase().contains("you may not"))
				return false;
			
			else if(tuple.toLowerCase().contains("reuse"))
				return false;
			
			else if(tuple.toLowerCase().contains("access may"))
				return false;
			
						
			else
			{
				for(String s : arr_dismiss_words)
				{
					if(tuple.toLowerCase().trim().contains(s.toLowerCase().trim()))
						return false;
				}
				
				driver.sop("Unknown field [" + tuple + "]");
			}
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "parse_whois_server", e);
			//e.printStackTrace(System.out);
		}
		
		return false;
	}
	
	public boolean parse_name_server(String tuple)
	{
		try
		{
			
			
			//e.g. dns2.nic.uk.        103.49.80.1       2401:fd80:400::1
			tuple = tuple.replaceAll("        ", " ");
			tuple = tuple.replaceAll("       ", " ");
			
			this.arr = tuple.split(" ");
			
			if(arr.length > 2)
			{
				set_name_server_name(arr[0], false);
				set_name_server_ip(arr[1]);
				set_name_server_ip(arr[2]);
			}
			
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "parse_name_server", e);
		}
		
		return false;
	}
	
	public boolean set_name_server_name(String value, boolean perform_ping)
	{
		try
		{
			if(value == null || value.trim().equals(""))
				return false;
			
			value = value.trim();
			
			if(this.list_name_server_names.contains(value))
			return false;
		
			this.list_name_server_names.add(value);
			
			if(this.name_server_NAME1 == null || this.name_server_NAME1.trim().equals("")) name_server_NAME1 = value;
			else if(this.name_server_NAME2 == null || this.name_server_NAME2.trim().equals("")) name_server_NAME2 = value;
			else if(this.name_server_NAME3 == null || this.name_server_NAME3.trim().equals("")) name_server_NAME3 = value;
			else if(this.name_server_NAME4 == null || this.name_server_NAME4.trim().equals("")) name_server_NAME4 = value;
			else if(this.name_server_NAME5 == null || this.name_server_NAME5.trim().equals("")) name_server_NAME5 = value;
			else if(this.name_server_NAME6 == null || this.name_server_NAME6.trim().equals("")) name_server_NAME6 = value;
			else if(this.name_server_NAME7 == null || this.name_server_NAME7.trim().equals("")) name_server_NAME7 = value;
			else if(this.name_server_NAME8 == null || this.name_server_NAME8.trim().equals("")) name_server_NAME8 = value;
			else if(this.name_server_NAME9 == null || this.name_server_NAME9.trim().equals("")) name_server_NAME9 = value;
			else if(this.name_server_NAME10 == null || this.name_server_NAME10.trim().equals("")) name_server_NAME10 = value;
			else if(this.name_server_NAME11 == null || this.name_server_NAME11.trim().equals("")) name_server_NAME11 = value;
			else if(this.name_server_NAME12 == null || this.name_server_NAME12.trim().equals("")) name_server_NAME12 = value;
			else if(this.name_server_NAME13 == null || this.name_server_NAME13.trim().equals("")) name_server_NAME13 = value;
			else if(this.name_server_NAME14 == null || this.name_server_NAME14.trim().equals("")) name_server_NAME14 = value;
			else if(this.name_server_NAME15 == null || this.name_server_NAME15.trim().equals("")) name_server_NAME15 = value;
			else if(this.name_server_NAME16 == null || this.name_server_NAME16.trim().equals("")) name_server_NAME16 = value;
			else if(this.name_server_NAME17 == null || this.name_server_NAME7.trim().equals("")) name_server_NAME17 = value;
			else if(this.name_server_NAME18 == null || this.name_server_NAME18.trim().equals("")) name_server_NAME18 = value;
			else if(this.name_server_NAME19 == null || this.name_server_NAME19.trim().equals("")) name_server_NAME19 = value;
			else if(this.name_server_NAME20 == null || this.name_server_NAME20.trim().equals("")) name_server_NAME20 = value;			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "set_name_server_name", e);
		}
		
		return false;
	}
	
	public boolean set_name_server_ip(String value)
	{
		try
		{
			if(value == null || value.trim().equals(""))
				return false;
			
			value = value.trim();
			
			if(this.list_name_server_ip.contains(value))
				return false;
			
			this.list_name_server_ip.add(value);
			
			if(this.name_server_IP1 == null || this.name_server_IP1.trim().equals("")) name_server_IP1 = value;
			else if(this.name_server_IP2 == null || this.name_server_IP2.trim().equals("")) name_server_IP2 = value;
			else if(this.name_server_IP3 == null || this.name_server_IP3.trim().equals("")) name_server_IP3 = value;
			else if(this.name_server_IP4 == null || this.name_server_IP4.trim().equals("")) name_server_IP4 = value;
			else if(this.name_server_IP5 == null || this.name_server_IP5.trim().equals("")) name_server_IP5 = value;
			else if(this.name_server_IP6 == null || this.name_server_IP6.trim().equals("")) name_server_IP6 = value;
			else if(this.name_server_IP7 == null || this.name_server_IP7.trim().equals("")) name_server_IP7 = value;
			else if(this.name_server_IP8 == null || this.name_server_IP8.trim().equals("")) name_server_IP8 = value;
			else if(this.name_server_IP9 == null || this.name_server_IP9.trim().equals("")) name_server_IP9 = value;
			else if(this.name_server_IP10 == null || this.name_server_IP10.trim().equals("")) name_server_IP10 = value;
			else if(this.name_server_IP11 == null || this.name_server_IP11.trim().equals("")) name_server_IP11 = value;
			else if(this.name_server_IP12 == null || this.name_server_IP12.trim().equals("")) name_server_IP12 = value;
			else if(this.name_server_IP13 == null || this.name_server_IP13.trim().equals("")) name_server_IP13 = value;
			else if(this.name_server_IP14 == null || this.name_server_IP14.trim().equals("")) name_server_IP14 = value;
			else if(this.name_server_IP15 == null || this.name_server_IP15.trim().equals("")) name_server_IP15 = value;
			else if(this.name_server_IP16 == null || this.name_server_IP16.trim().equals("")) name_server_IP16 = value;
			else if(this.name_server_IP17 == null || this.name_server_IP7.trim().equals("")) name_server_IP17 = value;
			else if(this.name_server_IP18 == null || this.name_server_IP18.trim().equals("")) name_server_IP18 = value;
			else if(this.name_server_IP19 == null || this.name_server_IP19.trim().equals("")) name_server_IP19 = value;
			else if(this.name_server_IP20 == null || this.name_server_IP20.trim().equals("")) name_server_IP20 = value;		
				
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "set_name_server_ip", e);
		}
		
		return false;
	}
	
	public boolean sop(String out)
	{
		try
		{
			driver.sop(out);
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "sop", e);
		}
		
		return false;
	}
	
	
	public static boolean update_geo()
	{
		try
		{
			//search through and attempt to update nodes without a geo allocation
			
			if(Node_GeoIP.geo_requests_per_hour_count > Node_GeoIP.max_geo_requests_per_hour)
				return false;
			
			for(Whois whois : Whois.tree_whois_lookup.values())
			{
				try
				{
					if(whois.node_geo == null || whois.node_geo.latitude == null || whois.node_geo.latitude.trim().equals(""))
					{
						//look it up, and assign if successful
						Node_GeoIP geo = new Node_GeoIP(whois.LOOKUP, false);
						
						if(geo.parse_complete)
							whois.node_geo = geo;
					}
						
				}
				catch(Exception e)
				{
					driver.eop_loop(myClassName, "update_geo", e, -1);
					continue;
				}
			}
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "update_geo", e);
		}
		
		return false;
	}
	
	public boolean check_special_parsing(String line)
	{
		try
		{
			if(line == null || line.trim().equals(""))
				return false;
			
			//but first check if we're not in a special save mode
			
			//dismiss invalid words
			for(String s : arr_dismiss_words)
			{
				if(line.toLowerCase().contains(s))
					return false;																
			}
			
			//check special case words
			//else, check if we're in the special storing mode, e.g. 1.co.uk. if so, proceed in reverse order to hit the least likely first bcs the others would be activated as well - Solo Sonya
			if(store_mode_NAME_SERVERS && !line.toLowerCase().equals(this.DOMAIN_NAME) && line.contains(".") && this.list_name_server_names != null && this.list_name_server_names.size() < 3)
			{
				set_name_server_name(line, false);
				//this.ping(line, 1, false);
			}
			
			else if(store_mode_REGISTRATION_STATUS)
			{
				if(this.registration_status == null || registration_status.trim().equals(""))
					registration_status = line.trim();
				/*else
					registration_status = registration_status.trim() + " " + line.trim();*/
			}
			
			else if(store_mode_REGISTRAR)
			{
				if(this.registrar == null || registrar.trim().equals(""))
					registrar = line.trim();
				/*else
					registrar = registrar.trim() + " " + line.trim();*/
			}
			
			else if(store_mode_DATA_VALIDATION)
			{
				if(this.data_validation == null || data_validation.trim().equals(""))
					data_validation = line.trim();
				/*else
					data_validation = data_validation.trim() + " " + line.trim();*/
			}
			
			else if(store_mode_REGISTRANT_ADDRESS)
			{
				if(this.registrant_street == null)
					registrant_street = line.trim();
				else if(!registrant_street.contains(line))
					registrant_street = registrant_street.trim() + " " + line.trim();
			}
			
			else if(store_mode_REGISTRANT_TYPE)
			{
				if(this.registrant_type == null || registrant_type.trim().equals(""))
					registrant_type = line.trim();
				else if(!registrant_type.contains(line))
					registrant_type = registrant_type.trim() + " " + line.trim();
			}
			
			else if(store_mode_REGISTRANT)
			{
				if(this.registrant_name == null || registrant_name.trim().equals(""))
					registrant_name = line.trim();
				/*else
					registrant_name = registrant_name.trim() + " " + line.trim();*/
								
			}
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "check_special_parsing", e);
		}
		
		return false;
	}
	
	
	
	public String get_name_server_list(String end_of_line_delimiter, boolean include_html_headers, boolean return_in_graph_format)
	{
		try
		{
			this.name_server_concat = "";
			
			if(this.name_server_NAME1 != null && !this.name_server_NAME1.trim().equals(""))
			{
				if(return_in_graph_format)
					name_server_concat = name_server_concat + "{source: \"Name Server\", target: " + "\"Name Server: " + name_server_NAME1 + "\", type: \"solid_green\"}, ";
				else if(include_html_headers)
					name_server_concat = name_server_concat + "<b>Name Server:</b> " + name_server_NAME1 + end_of_line_delimiter;
				else
					name_server_concat = name_server_concat + " Name Server: " + name_server_NAME1 + end_of_line_delimiter;
			}
			
			if(this.name_server_NAME2 != null && !this.name_server_NAME2.trim().equals(""))
			{
				if(return_in_graph_format)
					name_server_concat = name_server_concat + "{source: \"Name Server\", target: " + "\"Name Server: " + name_server_NAME2 + "\", type: \"solid_green\"}, ";
				else if(include_html_headers)
					name_server_concat = name_server_concat + "<b>Name Server:</b> " + name_server_NAME2 + end_of_line_delimiter;
				else
					name_server_concat = name_server_concat + " Name Server: " + name_server_NAME2 + end_of_line_delimiter;
			}
			
			if(this.name_server_NAME3 != null && !this.name_server_NAME3.trim().equals(""))
			{
				if(return_in_graph_format)
					name_server_concat = name_server_concat + "{source: \"Name Server\", target: " + "\"Name Server: " + name_server_NAME3 + "\", type: \"solid_green\"}, ";
				else if(include_html_headers)
					name_server_concat = name_server_concat + "<b>Name Server:</b> " + name_server_NAME3 + end_of_line_delimiter;
				else
					name_server_concat = name_server_concat + " Name Server: " + name_server_NAME3 + end_of_line_delimiter;
			}
			
			if(this.name_server_NAME4 != null && !this.name_server_NAME4.trim().equals(""))
			{
				if(return_in_graph_format)
					name_server_concat = name_server_concat + "{source: \"Name Server\", target: " + "\"Name Server: " + name_server_NAME4 + "\", type: \"solid_green\"}, ";
				else if(include_html_headers)
					name_server_concat = name_server_concat + "<b>Name Server:</b> " + name_server_NAME4 + end_of_line_delimiter;
				else
					name_server_concat = name_server_concat + " Name Server: " + name_server_NAME4 + end_of_line_delimiter;
			}
			
			if(this.name_server_NAME5 != null && !this.name_server_NAME5.trim().equals(""))
			{
				if(return_in_graph_format)
					name_server_concat = name_server_concat + "{source: \"Name Server\", target: " + "\"Name Server: " + name_server_NAME5 + "\", type: \"solid_green\"}, ";
				else if(include_html_headers)
					name_server_concat = name_server_concat + "<b>Name Server:</b> " + name_server_NAME5 + end_of_line_delimiter;
				else
					name_server_concat = name_server_concat + " Name Server: " + name_server_NAME5 + end_of_line_delimiter;
			}
			
			if(this.name_server_NAME6 != null && !this.name_server_NAME6.trim().equals(""))
			{
				if(return_in_graph_format)
					name_server_concat = name_server_concat + "{source: \"Name Server\", target: " + "\"Name Server: " + name_server_NAME6 + "\", type: \"solid_green\"}, ";
				else if(include_html_headers)
					name_server_concat = name_server_concat + "<b>Name Server:</b> " + name_server_NAME6 + end_of_line_delimiter;
				else
					name_server_concat = name_server_concat + " Name Server: " + name_server_NAME6 + end_of_line_delimiter;
			}
			
			if(this.name_server_NAME7 != null && !this.name_server_NAME7.trim().equals(""))
			{
				if(return_in_graph_format)
					name_server_concat = name_server_concat + "{source: \"Name Server\", target: " + "\"Name Server: " + name_server_NAME7 + "\", type: \"solid_green\"}, ";
				else if(include_html_headers)
					name_server_concat = name_server_concat + "<b>Name Server:</b> " + name_server_NAME7 + end_of_line_delimiter;
				else
					name_server_concat = name_server_concat + " Name Server: " + name_server_NAME7 + end_of_line_delimiter;
			}
			
			if(this.name_server_NAME8 != null && !this.name_server_NAME8.trim().equals(""))
			{
				if(return_in_graph_format)
					name_server_concat = name_server_concat + "{source: \"Name Server\", target: " + "\"Name Server: " + name_server_NAME8 + "\", type: \"solid_green\"}, ";
				else if(include_html_headers)
					name_server_concat = name_server_concat + "<b>Name Server:</b> " + name_server_NAME8 + end_of_line_delimiter;
				else
					name_server_concat = name_server_concat + " Name Server: " + name_server_NAME8 + end_of_line_delimiter;
			}
			
			if(this.name_server_NAME9 != null && !this.name_server_NAME9.trim().equals(""))
			{
				if(return_in_graph_format)
					name_server_concat = name_server_concat + "{source: \"Name Server\", target: " + "\"Name Server: " + name_server_NAME9 + "\", type: \"solid_green\"}, ";
				else if(include_html_headers)
					name_server_concat = name_server_concat + "<b>Name Server:</b> " + name_server_NAME9 + end_of_line_delimiter;
				else
					name_server_concat = name_server_concat + " Name Server: " + name_server_NAME9 + end_of_line_delimiter;
			}
			
			if(this.name_server_NAME10 != null && !this.name_server_NAME10.trim().equals(""))
			{
				if(return_in_graph_format)
					name_server_concat = name_server_concat + "{source: \"Name Server\", target: " + "\"Name Server: " + name_server_NAME10 + "\", type: \"solid_green\"}, ";
				else if(include_html_headers)
					name_server_concat = name_server_concat + "<b>Name Server:</b> " + name_server_NAME10 + end_of_line_delimiter;
				else
					name_server_concat = name_server_concat + " Name Server: " + name_server_NAME10 + end_of_line_delimiter;
			}
			
			if(this.name_server_NAME11 != null && !this.name_server_NAME11.trim().equals(""))
			{
				if(return_in_graph_format)
					name_server_concat = name_server_concat + "{source: \"Name Server\", target: " + "\"Name Server: " + name_server_NAME11 + "\", type: \"solid_green\"}, ";
				else if(include_html_headers)
					name_server_concat = name_server_concat + "<b>Name Server:</b> " + name_server_NAME11 + end_of_line_delimiter;
				else
					name_server_concat = name_server_concat + " Name Server: " + name_server_NAME11 + end_of_line_delimiter;			
			}
			
			if(this.name_server_NAME12 != null && !this.name_server_NAME12.trim().equals(""))
			{
				if(return_in_graph_format)
					name_server_concat = name_server_concat + "{source: \"Name Server\", target: " + "\"Name Server: " + name_server_NAME12 + "\", type: \"solid_green\"}, ";
				else if(include_html_headers)
					name_server_concat = name_server_concat + "<b>Name Server:</b> " + name_server_NAME12 + end_of_line_delimiter;
				else
					name_server_concat = name_server_concat + " Name Server: " + name_server_NAME12 + end_of_line_delimiter;
			}
			
			if(this.name_server_NAME13 != null && !this.name_server_NAME13.trim().equals(""))
			{
				if(return_in_graph_format)
					name_server_concat = name_server_concat + "{source: \"Name Server\", target: " + "\"Name Server: " + name_server_NAME13 + "\", type: \"solid_green\"}, ";
				else if(include_html_headers)
					name_server_concat = name_server_concat + "<b>Name Server:</b> " + name_server_NAME13 + end_of_line_delimiter;
				else
					name_server_concat = name_server_concat + " Name Server: " + name_server_NAME13 + end_of_line_delimiter;
			}
			
			if(this.name_server_NAME14 != null && !this.name_server_NAME14.trim().equals(""))
			{
				if(return_in_graph_format)
					name_server_concat = name_server_concat + "{source: \"Name Server\", target: " + "\"Name Server: " + name_server_NAME14 + "\", type: \"solid_green\"}, ";
				else if(include_html_headers)
					name_server_concat = name_server_concat + "<b>Name Server:</b> " + name_server_NAME14 + end_of_line_delimiter;
				else
					name_server_concat = name_server_concat + " Name Server: " + name_server_NAME14 + end_of_line_delimiter;
			}
			
			if(this.name_server_NAME15 != null && !this.name_server_NAME15.trim().equals(""))
			{
				if(return_in_graph_format)
					name_server_concat = name_server_concat + "{source: \"Name Server\", target: " + "\"Name Server: " + name_server_NAME15 + "\", type: \"solid_green\"}, ";
				else if(include_html_headers)
					name_server_concat = name_server_concat + "<b>Name Server:</b> " + name_server_NAME15 + end_of_line_delimiter;
				else
					name_server_concat = name_server_concat + " Name Server: " + name_server_NAME15 + end_of_line_delimiter;
			}
			
			if(this.name_server_NAME16 != null && !this.name_server_NAME16.trim().equals(""))
			{
				if(return_in_graph_format)
					name_server_concat = name_server_concat + "{source: \"Name Server\", target: " + "\"Name Server: " + name_server_NAME16 + "\", type: \"solid_green\"}, ";
				else if(include_html_headers)
					name_server_concat = name_server_concat + "<b>Name Server:</b> " + name_server_NAME16 + end_of_line_delimiter;
				else
					name_server_concat = name_server_concat + " Name Server: " + name_server_NAME16 + end_of_line_delimiter;
			}
			
			if(this.name_server_NAME17 != null && !this.name_server_NAME17.trim().equals(""))
			{
				if(return_in_graph_format)
					name_server_concat = name_server_concat + "{source: \"Name Server\", target: " + "\"Name Server: " + name_server_NAME17 + "\", type: \"solid_green\"}, ";
				else if(include_html_headers)
					name_server_concat = name_server_concat + "<b>Name Server:</b> " + name_server_NAME17 + end_of_line_delimiter;
				else
					name_server_concat = name_server_concat + " Name Server: " + name_server_NAME17 + end_of_line_delimiter;
			}
			
			if(this.name_server_NAME18 != null && !this.name_server_NAME18.trim().equals(""))
			{
				if(return_in_graph_format)
					name_server_concat = name_server_concat + "{source: \"Name Server\", target: " + "\"Name Server: " + name_server_NAME18 + "\", type: \"solid_green\"}, ";
				else if(include_html_headers)
					name_server_concat = name_server_concat + "<b>Name Server:</b> " + name_server_NAME18 + end_of_line_delimiter;
				else
					name_server_concat = name_server_concat + " Name Server: " + name_server_NAME18 + end_of_line_delimiter;
			}
			
			if(this.name_server_NAME19 != null && !this.name_server_NAME19.trim().equals(""))
			{
				if(return_in_graph_format)
					name_server_concat = name_server_concat + "{source: \"Name Server\", target: " + "\"Name Server: " + name_server_NAME19 + "\", type: \"solid_green\"}, ";
				else if(include_html_headers)
					name_server_concat = name_server_concat + "<b>Name Server:</b> " + name_server_NAME19 + end_of_line_delimiter;
				else
					name_server_concat = name_server_concat + " Name Server: " + name_server_NAME19 + end_of_line_delimiter;
			}
			
			if(this.name_server_NAME20 != null && !this.name_server_NAME20.trim().equals(""))
			{
				if(return_in_graph_format)
					name_server_concat = name_server_concat + "{source: \"Name Server\", target: " + "\"Name Server: " + name_server_NAME20 + "\", type: \"solid_green\"}, ";
				else if(include_html_headers)
					name_server_concat = name_server_concat + "<b>Name Server:</b> " + name_server_NAME20 + end_of_line_delimiter;
				else
					name_server_concat = name_server_concat + " Name Server: " + name_server_NAME20 + end_of_line_delimiter;
			}
			
			return name_server_concat;
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "get_name_server", e);
		}
		
		return "name server:" + this.name_server_NAME1;
	}
	
	
	
	public String get_name_server_IP_list(String end_of_line_delimiter, boolean include_html_headers, boolean return_in_graph_format)
	{
		try
		{
			this.name_server_concat = "";
			
			if(this.name_server_IP1 != null && !this.name_server_IP1.trim().equals(""))
			{
				if(return_in_graph_format)
					name_server_concat = name_server_concat + "{source: \"Name Server IP\", target: " + "\"Name Server IP: " + name_server_IP1 + "\", type: \"solid_brown\"}, ";
				else if(include_html_headers)
					name_server_concat = name_server_concat + "<b>Name Server IP:</b> " + name_server_IP1 + end_of_line_delimiter;
				else
					name_server_concat = name_server_concat + " Name Server IP: " + name_server_IP1 + end_of_line_delimiter;
			}
			
			if(this.name_server_IP2 != null && !this.name_server_IP2.trim().equals(""))
			{
				if(return_in_graph_format)
					name_server_concat = name_server_concat + "{source: \"Name Server IP\", target: " + "\"Name Server IP: " + name_server_IP2 + "\", type: \"solid_brown\"}, ";
				else if(include_html_headers)
					name_server_concat = name_server_concat + "<b>Name Server IP:</b> " + name_server_IP2 + end_of_line_delimiter;
				else
					name_server_concat = name_server_concat + " Name Server IP: " + name_server_IP2 + end_of_line_delimiter;
			}
			
			if(this.name_server_IP3 != null && !this.name_server_IP3.trim().equals(""))
			{
				if(return_in_graph_format)
					name_server_concat = name_server_concat + "{source: \"Name Server IP\", target: " + "\"Name Server IP: " + name_server_IP3 + "\", type: \"solid_brown\"}, ";
				else if(include_html_headers)
					name_server_concat = name_server_concat + "<b>Name Server IP:</b> " + name_server_IP3 + end_of_line_delimiter;
				else
					name_server_concat = name_server_concat + " Name Server IP: " + name_server_IP3 + end_of_line_delimiter;
			}
			
			if(this.name_server_IP4 != null && !this.name_server_IP4.trim().equals(""))
			{
				if(return_in_graph_format)
					name_server_concat = name_server_concat + "{source: \"Name Server IP\", target: " + "\"Name Server IP: " + name_server_IP4 + "\", type: \"solid_brown\"}, ";
				else if(include_html_headers)
					name_server_concat = name_server_concat + "<b>Name Server IP:</b> " + name_server_IP4 + end_of_line_delimiter;
				else
					name_server_concat = name_server_concat + " Name Server IP: " + name_server_IP4 + end_of_line_delimiter;
			}
			
			if(this.name_server_IP5 != null && !this.name_server_IP5.trim().equals(""))
			{
				if(return_in_graph_format)
					name_server_concat = name_server_concat + "{source: \"Name Server IP\", target: " + "\"Name Server IP: " + name_server_IP5 + "\", type: \"solid_brown\"}, ";
				else if(include_html_headers)
					name_server_concat = name_server_concat + "<b>Name Server IP:</b> " + name_server_IP5 + end_of_line_delimiter;
				else
					name_server_concat = name_server_concat + " Name Server IP: " + name_server_IP5 + end_of_line_delimiter;
			}
			
			if(this.name_server_IP6 != null && !this.name_server_IP6.trim().equals(""))
			{
				if(return_in_graph_format)
					name_server_concat = name_server_concat + "{source: \"Name Server IP\", target: " + "\"Name Server IP: " + name_server_IP6 + "\", type: \"solid_brown\"}, ";
				else if(include_html_headers)
					name_server_concat = name_server_concat + "<b>Name Server IP:</b> " + name_server_IP6 + end_of_line_delimiter;
				else
					name_server_concat = name_server_concat + " Name Server IP: " + name_server_IP6 + end_of_line_delimiter;
			}
			
			if(this.name_server_IP7 != null && !this.name_server_IP7.trim().equals(""))
			{
				if(return_in_graph_format)
					name_server_concat = name_server_concat + "{source: \"Name Server IP\", target: " + "\"Name Server IP: " + name_server_IP7 + "\", type: \"solid_brown\"}, ";
				else if(include_html_headers)
					name_server_concat = name_server_concat + "<b>Name Server IP:</b> " + name_server_IP7 + end_of_line_delimiter;
				else
					name_server_concat = name_server_concat + " Name Server IP: " + name_server_IP7 + end_of_line_delimiter;
			}
			
			if(this.name_server_IP8 != null && !this.name_server_IP8.trim().equals(""))
			{
				if(return_in_graph_format)
					name_server_concat = name_server_concat + "{source: \"Name Server IP\", target: " + "\"Name Server IP: " + name_server_IP8 + "\", type: \"solid_brown\"}, ";
				else if(include_html_headers)
					name_server_concat = name_server_concat + "<b>Name Server IP:</b> " + name_server_IP8 + end_of_line_delimiter;
				else
					name_server_concat = name_server_concat + " Name Server IP: " + name_server_IP8 + end_of_line_delimiter;
			}
			
			if(this.name_server_IP9 != null && !this.name_server_IP9.trim().equals(""))
			{
				if(return_in_graph_format)
					name_server_concat = name_server_concat + "{source: \"Name Server IP\", target: " + "\"Name Server IP: " + name_server_IP9 + "\", type: \"solid_brown\"}, ";
				else if(include_html_headers)
					name_server_concat = name_server_concat + "<b>Name Server IP:</b> " + name_server_IP9 + end_of_line_delimiter;
				else
					name_server_concat = name_server_concat + " Name Server IP: " + name_server_IP9 + end_of_line_delimiter;
			}
			
			if(this.name_server_IP10 != null && !this.name_server_IP10.trim().equals(""))
			{
				if(return_in_graph_format)
					name_server_concat = name_server_concat + "{source: \"Name Server IP\", target: " + "\"Name Server IP: " + name_server_IP10 + "\", type: \"solid_brown\"}, ";
				else if(include_html_headers)
					name_server_concat = name_server_concat + "<b>Name Server IP:</b> " + name_server_IP10 + end_of_line_delimiter;
				else
					name_server_concat = name_server_concat + " Name Server IP: " + name_server_IP10 + end_of_line_delimiter;
			}
			
			if(this.name_server_IP11 != null && !this.name_server_IP11.trim().equals(""))
			{
				if(return_in_graph_format)
					name_server_concat = name_server_concat + "{source: \"Name Server IP\", target: " + "\"Name Server IP: " + name_server_IP11 + "\", type: \"solid_brown\"}, ";
				else if(include_html_headers)
					name_server_concat = name_server_concat + "<b>Name Server IP:</b> " + name_server_IP11 + end_of_line_delimiter;
				else
					name_server_concat = name_server_concat + " Name Server IP: " + name_server_IP11 + end_of_line_delimiter;			
			}
			
			if(this.name_server_IP12 != null && !this.name_server_IP12.trim().equals(""))
			{
				if(return_in_graph_format)
					name_server_concat = name_server_concat + "{source: \"Name Server IP\", target: " + "\"Name Server IP: " + name_server_IP12 + "\", type: \"solid_brown\"}, ";
				else if(include_html_headers)
					name_server_concat = name_server_concat + "<b>Name Server IP:</b> " + name_server_IP12 + end_of_line_delimiter;
				else
					name_server_concat = name_server_concat + " Name Server IP: " + name_server_IP12 + end_of_line_delimiter;
			}
			
			if(this.name_server_IP13 != null && !this.name_server_IP13.trim().equals(""))
			{
				if(return_in_graph_format)
					name_server_concat = name_server_concat + "{source: \"Name Server IP\", target: " + "\"Name Server IP: " + name_server_IP13 + "\", type: \"solid_brown\"}, ";
				else if(include_html_headers)
					name_server_concat = name_server_concat + "<b>Name Server IP:</b> " + name_server_IP13 + end_of_line_delimiter;
				else
					name_server_concat = name_server_concat + " Name Server IP: " + name_server_IP13 + end_of_line_delimiter;
			}
			
			if(this.name_server_IP14 != null && !this.name_server_IP14.trim().equals(""))
			{
				if(return_in_graph_format)
					name_server_concat = name_server_concat + "{source: \"Name Server IP\", target: " + "\"Name Server IP: " + name_server_IP14 + "\", type: \"solid_brown\"}, ";
				else if(include_html_headers)
					name_server_concat = name_server_concat + "<b>Name Server IP:</b> " + name_server_IP14 + end_of_line_delimiter;
				else
					name_server_concat = name_server_concat + " Name Server IP: " + name_server_IP14 + end_of_line_delimiter;
			}
			
			if(this.name_server_IP15 != null && !this.name_server_IP15.trim().equals(""))
			{
				if(return_in_graph_format)
					name_server_concat = name_server_concat + "{source: \"Name Server IP\", target: " + "\"Name Server IP: " + name_server_IP15 + "\", type: \"solid_brown\"}, ";
				else if(include_html_headers)
					name_server_concat = name_server_concat + "<b>Name Server IP:</b> " + name_server_IP15 + end_of_line_delimiter;
				else
					name_server_concat = name_server_concat + " Name Server IP: " + name_server_IP15 + end_of_line_delimiter;
			}
			
			if(this.name_server_IP16 != null && !this.name_server_IP16.trim().equals(""))
			{
				if(return_in_graph_format)
					name_server_concat = name_server_concat + "{source: \"Name Server IP\", target: " + "\"Name Server IP: " + name_server_IP16 + "\", type: \"solid_brown\"}, ";
				else if(include_html_headers)
					name_server_concat = name_server_concat + "<b>Name Server IP:</b> " + name_server_IP16 + end_of_line_delimiter;
				else
					name_server_concat = name_server_concat + " Name Server IP: " + name_server_IP16 + end_of_line_delimiter;
			}
			
			if(this.name_server_IP17 != null && !this.name_server_IP17.trim().equals(""))
			{
				if(return_in_graph_format)
					name_server_concat = name_server_concat + "{source: \"Name Server IP\", target: " + "\"Name Server IP: " + name_server_IP17 + "\", type: \"solid_brown\"}, ";
				else if(include_html_headers)
					name_server_concat = name_server_concat + "<b>Name Server IP:</b> " + name_server_IP17 + end_of_line_delimiter;
				else
					name_server_concat = name_server_concat + " Name Server IP: " + name_server_IP17 + end_of_line_delimiter;
			}
			
			if(this.name_server_IP18 != null && !this.name_server_IP18.trim().equals(""))
			{
				if(return_in_graph_format)
					name_server_concat = name_server_concat + "{source: \"Name Server IP\", target: " + "\"Name Server IP: " + name_server_IP18 + "\", type: \"solid_brown\"}, ";
				else if(include_html_headers)
					name_server_concat = name_server_concat + "<b>Name Server IP:</b> " + name_server_IP18 + end_of_line_delimiter;
				else
					name_server_concat = name_server_concat + " Name Server IP: " + name_server_IP18 + end_of_line_delimiter;
			}
			
			if(this.name_server_IP19 != null && !this.name_server_IP19.trim().equals(""))
			{
				if(return_in_graph_format)
					name_server_concat = name_server_concat + "{source: \"Name Server IP\", target: " + "\"Name Server IP: " + name_server_IP19 + "\", type: \"solid_brown\"}, ";
				else if(include_html_headers)
					name_server_concat = name_server_concat + "<b>Name Server IP:</b> " + name_server_IP19 + end_of_line_delimiter;
				else
					name_server_concat = name_server_concat + " Name Server IP: " + name_server_IP19 + end_of_line_delimiter;
			}
			
			if(this.name_server_IP20 != null && !this.name_server_IP20.trim().equals(""))
			{
				if(return_in_graph_format)
					name_server_concat = name_server_concat + "{source: \"Name Server IP\", target: " + "\"Name Server IP: " + name_server_IP20 + "\", type: \"solid_brown\"}, ";
				else if(include_html_headers)
					name_server_concat = name_server_concat + "<b>Name Server IP:</b> " + name_server_IP20 + end_of_line_delimiter;
				else
					name_server_concat = name_server_concat + " Name Server IP: " + name_server_IP20 + end_of_line_delimiter;
			}
			
			return name_server_concat;
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "get_name_server_IP_list", e);
		}
		
		return "name server ip:" + this.name_server_IP1;
	}
	
	
	public String get_domain_status_list(String end_of_line_delimiter, boolean include_html_headers)
	{
		try
		{
			this.domain_status_concat = "";
			
			if(this.domain_status1 != null && !this.domain_status1.trim().equals(""))
			{
				if(include_html_headers)
					domain_status_concat = domain_status_concat + "<b>Domain Status:</b> " + domain_status1 + end_of_line_delimiter;
				else
					domain_status_concat = domain_status_concat + "Domain Status: " + domain_status1 + end_of_line_delimiter;
			}
			
			if(this.domain_status2 != null && !this.domain_status2.trim().equals(""))
			{
				if(include_html_headers)
					domain_status_concat = domain_status_concat + "<b>Domain Status:</b> " + domain_status2 + end_of_line_delimiter;
				else
					domain_status_concat = domain_status_concat +  "Domain Status: " + domain_status2 + end_of_line_delimiter;
			}
			
			if(this.domain_status3 != null && !this.domain_status3.trim().equals(""))
			{
				if(include_html_headers)
					domain_status_concat = domain_status_concat + "<b>Domain Status:</b> " + domain_status3 + end_of_line_delimiter;
				else
					domain_status_concat = domain_status_concat +  "Domain Status: " + domain_status3 + end_of_line_delimiter;
			}
			
			if(this.domain_status4 != null && !this.domain_status4.trim().equals(""))
			{
				if(include_html_headers)
					domain_status_concat = domain_status_concat + "<b>Domain Status:</b> " + domain_status4 + end_of_line_delimiter;
				else
					domain_status_concat = domain_status_concat +  "Domain Status: " + domain_status4 + end_of_line_delimiter;
			}
			
			if(this.domain_status5 != null && !this.domain_status5.trim().equals(""))
			{
				if(include_html_headers)
					domain_status_concat = domain_status_concat + "<b>Domain Status:</b> " + domain_status5 + end_of_line_delimiter;
				else
					domain_status_concat = domain_status_concat +  "Domain Status: " + domain_status5 + end_of_line_delimiter;
			}
			
			if(this.domain_status6 != null && !this.domain_status6.trim().equals(""))
			{
				if(include_html_headers)
					domain_status_concat = domain_status_concat + "<b>Domain Status:</b> " + domain_status6 + end_of_line_delimiter;
				else
					domain_status_concat = domain_status_concat +  "Domain Status: " + domain_status6 + end_of_line_delimiter;
			}
			
			if(this.domain_status7 != null && !this.domain_status7.trim().equals(""))
			{
				if(include_html_headers)
					domain_status_concat = domain_status_concat + "<b>Domain Status:</b> " + domain_status7 + end_of_line_delimiter;
				else
					domain_status_concat = domain_status_concat +  "Domain Status: " + domain_status7 + end_of_line_delimiter;
			}
			
			if(this.domain_status8 != null && !this.domain_status8.trim().equals(""))
			{
				if(include_html_headers)
					domain_status_concat = domain_status_concat + "<b>Domain Status:</b> " + domain_status8 + end_of_line_delimiter;
				else
					domain_status_concat = domain_status_concat +  "Domain Status: " + domain_status8 + end_of_line_delimiter;
			}
			
			if(this.domain_status9 != null && !this.domain_status9.trim().equals(""))
			{
				if(include_html_headers)
					domain_status_concat = domain_status_concat + "<b>Domain Status:</b> " + domain_status9 + end_of_line_delimiter;
				else
					domain_status_concat = domain_status_concat +  "Domain Status: " + domain_status9 + end_of_line_delimiter;
			}
			
			if(this.domain_status10 != null && !this.domain_status10.trim().equals(""))
			{
				if(include_html_headers)
					domain_status_concat = domain_status_concat + "<b>Domain Status:</b> " + domain_status10 + end_of_line_delimiter;
				else
					domain_status_concat = domain_status_concat +  "Domain Status: " + domain_status10 + end_of_line_delimiter;
			}
			
			
			
			return this.domain_status_concat;
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "get_domain_status", e);
		}
		
		return "domain status:" + this.domain_status1;
	}
	
	
	public boolean process_ioc(String line)
	{
		try
		{
			String ioc_value = line.substring(ioc_alert_text_length).replaceFirst("\\[", "").replaceFirst("\\]", "").toLowerCase().trim();
			
			if(ioc_value != null && !ioc_value.equals(""))
			{
				if(!this.tree_ioc_value.containsKey(ioc_value))
				{
					tree_ioc_value.put(ioc_value, null);
					new_ioc_entry = true;
				}
				
				//Alert the Resource and Source nodes
				if(Resolution.TREE_RESOURCE != null && Resolution.TREE_RESOURCE.containsKey(ioc_value))
				{
					Resolution resource = Resolution.TREE_RESOURCE.get(ioc_value);
					
					if(resource != null)
					{
						//IOC found!
						resource.ALERT = true;
						resource.alert_indicator = "*";

						if(resource.list_ioc == null)
							resource.list_ioc = new LinkedList<String>();
						
						if(!resource.list_ioc.contains(ioc_value))
						{
							resource.list_ioc.add(ioc_value);
							
							StandardInListener.intrface.jtbl_ALERTS.addRow(new String [] {resource.address, driver.time.getTime_Current_hyphenated_with_seconds("-"), "IOC-IDS", ioc_value, "ioc: " + ioc_value});
							StandardInListener.intrface.jtbl_ALERTS.jlblNumRows.setText("" + StandardInListener.intrface.jtbl_ALERTS.jtblMyJTbl.getRowCount());
						}
						
						//update source nodes communicating with this device
						if(resource.tree_source != null)
						{
							for(SOURCE source : resource.tree_source.values())
							{
								if(source == null)
									continue;
								
								//IOC found!																							
								if(!source.ALERT_DATABASE.containsKey(ioc_value))
								{
									source.ALERT = true;
									source.alert_indicator = "*";
									
									source.ALERT_DATABASE.put(ioc_value, "IOC: " + ioc_value + "\t" + driver.time.getTime_Current_hyphenated_with_seconds("-"));
																						
									StandardInListener.intrface.jtbl_ALERTS.addRow(new String [] {source.src_ip, driver.time.getTime_Current_hyphenated_with_seconds("-"), "IOC-IDS", ioc_value, "ioc: " + ioc_value});
									StandardInListener.intrface.jtbl_ALERTS.jlblNumRows.setText("" + StandardInListener.intrface.jtbl_ALERTS.jtblMyJTbl.getRowCount());
									
									//Log
									if(Parser.ALERT_LOG == null)
									{
										Parser.ALERT_LOG = new Log("parser/ALERT/",  "alert", 250, 999999999);
										Parser.ALERT_LOG.OVERRIDE_LOGGING_ENABLED = true;
										Parser.ALERT_LOG.log_directly("SOURCE" + " \t" + "TIME" + "\t" + "DETECTION_SYSTEM" + " \t" + "SIGNATURE" + " \t" + "DETAILS");
									}						
									
									Parser.ALERT_LOG.log_directly(resource.address + " \t" + driver.time.getTime_Current_hyphenated_with_seconds("-") + "\t" + "EXCALIBUR_IDS" + " \t" + ioc_value + " \t" + "Source Node: [" + source.src_ip + "] requested resource name [" + resource.address + "] that matched IOC value [" + ioc_value + "]");					
									
								}
							}
						}
					}
					
					if(Parser.ALERT_LOG == null)
					{
						Parser.ALERT_LOG = new Log("parser/ALERT/",  "alert", 250, 999999999);
						Parser.ALERT_LOG.OVERRIDE_LOGGING_ENABLED = true;
						Parser.ALERT_LOG.log_directly("SOURCE" + " \t" + "TIME" + "\t" + "DETECTION_SYSTEM" + " \t" + "SIGNATURE" + " \t" + "DETAILS");
					}						
					
					Parser.ALERT_LOG.log_directly(resource.address + " \t" + driver.time.getTime_Current_hyphenated_with_seconds("-") + "\t" + "EXCALIBUR_IDS" + " \t" + ioc_value + " \t" + "Requested resource name [" + resource.address + "] matched IOC value [" + ioc_value + "]");					
					
				}
				
				else if(new_ioc_entry)//node doesn't exist yet
				{
					StandardInListener.intrface.jtbl_ALERTS.addRow(new String [] {"Detected IOC: " + ioc_value, driver.time.getTime_Current_hyphenated_with_seconds("-"), "IOC IDS", ioc_value, "ioc: " + ioc_value});
					StandardInListener.intrface.jtbl_ALERTS.jlblNumRows.setText("" + StandardInListener.intrface.jtbl_ALERTS.jtblMyJTbl.getRowCount());
					new_ioc_entry = false;
					
					//
					//LOG ALERT
					//
					//
					if(Parser.ALERT_LOG == null)
					{
						Parser.ALERT_LOG = new Log("parser/ALERT/",  "alert", 250, 999999999);
						Parser.ALERT_LOG.OVERRIDE_LOGGING_ENABLED = true;
						Parser.ALERT_LOG.log_directly("SOURCE" + " \t" + "TIME" + "\t" + "DETECTION_SYSTEM" + " \t" + "SIGNATURE" + " \t" + "DETAILS");
					}						
					
					Parser.ALERT_LOG.log_directly(ioc_value + " \t" + driver.time.getTime_Current_hyphenated_with_seconds("-") + "\t" + "EXCALIBUR-IDS" + " \t" + ioc_value + " \t" + "Communication matched IOC value [" + ioc_value + "]");
					
				}
				
				
				
				if(SOURCE.TREE_SOURCE_NODES != null && SOURCE.TREE_SOURCE_NODES.containsKey(ioc_value))
				{
					SOURCE source = SOURCE.TREE_SOURCE_NODES.get(ioc_value);
					
					if(source != null)
					{
						//IOC found!
						source.ALERT = true;
						source.alert_indicator = "*";
													
						if(!source.ALERT_DATABASE.containsKey(ioc_value))
						{
							source.ALERT_DATABASE.put(ioc_value, "IOC: " + ioc_value + "\t" + driver.time.getTime_Current_hyphenated_with_seconds("-"));
																				
							StandardInListener.intrface.jtbl_ALERTS.addRow(new String [] {source.src_ip, driver.time.getTime_Current_hyphenated_with_seconds("-"), "IOC-IDS", ioc_value, "ioc: " + ioc_value});
							StandardInListener.intrface.jtbl_ALERTS.jlblNumRows.setText("" + StandardInListener.intrface.jtbl_ALERTS.jtblMyJTbl.getRowCount());
						}
						
						//
						//LOG ALERT
						//
						//
						if(Parser.ALERT_LOG == null)
						{
							Parser.ALERT_LOG = new Log("parser/ALERT/",  "alert", 250, 999999999);
							Parser.ALERT_LOG.OVERRIDE_LOGGING_ENABLED = true;
							Parser.ALERT_LOG.log_directly("SOURCE" + " \t" + "TIME" + "\t" + "DETECTION_SYSTEM" + " \t" + "SIGNATURE" + " \t" + "DETAILS");
						}						
						
						Parser.ALERT_LOG.log_directly(source.src_ip + " \t" + driver.time.getTime_Current_hyphenated_with_seconds("-") + "\t" + "EXCALIBUR IDS" + " \t" + ioc_value + " \t" + "Communication with source node [" + source.src_ip + "] matched IOC value [" + ioc_value + "]");
						
					}					
					
				}
				
				else if(new_ioc_entry)//node doesn't exist yet
				{
					StandardInListener.intrface.jtbl_ALERTS.addRow(new String [] {"Detected IOC: " + ioc_value, driver.time.getTime_Current_hyphenated_with_seconds("-"), "IOC_IDS", ioc_value, "ioc: " + ioc_value});
					StandardInListener.intrface.jtbl_ALERTS.jlblNumRows.setText("" + StandardInListener.intrface.jtbl_ALERTS.jtblMyJTbl.getRowCount());
					
					//
					//LOG ALERT
					//
					//
					if(Parser.ALERT_LOG == null)
					{
						Parser.ALERT_LOG = new Log("parser/ALERT/",  "alert", 250, 999999999);
						Parser.ALERT_LOG.OVERRIDE_LOGGING_ENABLED = true;
						Parser.ALERT_LOG.log_directly("SOURCE" + " \t" + "TIME" + "\t" + "DETECTION_SYSTEM" + " \t" + "SIGNATURE" + " \t" + "DETAILS");
					}						
					
					Parser.ALERT_LOG.log_directly(ioc_value + " \t" + driver.time.getTime_Current_hyphenated_with_seconds("-") + "\t" + "EXCALIBUR_IDS" + " \t" + ioc_value + " \t" + "Communication matched IOC value [" + ioc_value + "]");
					
				}
				
				
				
			}
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "process_ioc", e);
		}
		
		return false;
	}
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	

}
