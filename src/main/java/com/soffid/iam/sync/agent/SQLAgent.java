package com.soffid.iam.sync.agent;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.Method;
import java.math.BigDecimal;
import java.rmi.RemoteException;
import java.security.MessageDigest;
import java.sql.CallableStatement;
import java.sql.Connection;
import java.sql.Driver;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Types;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import org.json.JSONException;

import com.soffid.iam.api.AccountStatus;
import com.soffid.iam.api.DataType;
import com.soffid.iam.api.Group;
import com.soffid.iam.api.Host;
import com.soffid.iam.api.HostService;
import com.soffid.iam.api.RoleGrant;

import com.soffid.iam.api.Account;
import com.soffid.iam.api.ObjectMappingTrigger;
import com.soffid.iam.api.Password;
import com.soffid.iam.api.Role;
import com.soffid.iam.api.RoleGrant;
import com.soffid.iam.api.SoffidObjectType;
import com.soffid.iam.api.User;
import com.soffid.iam.remote.RemoteServiceLocator;
import com.soffid.iam.service.AdditionalDataService;

import es.caib.seycon.ng.comu.SoffidObjectTrigger;
import es.caib.seycon.ng.comu.TypeEnumeration;
import es.caib.seycon.ng.exception.AccountAlreadyExistsException;
import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.ng.exception.UnknownUserException;
import es.caib.seycon.ng.sync.bootstrap.NullSqlObjet;
import es.caib.seycon.ng.sync.bootstrap.QueryHelper;

import com.soffid.iam.sync.agent.Agent;
import com.soffid.iam.sync.engine.extobj.AccountExtensibleObject;
import com.soffid.iam.sync.engine.extobj.ExtensibleObjectFinder;
import com.soffid.iam.sync.engine.extobj.GrantExtensibleObject;
import com.soffid.iam.sync.engine.extobj.GroupExtensibleObject;
import com.soffid.iam.sync.engine.extobj.ObjectTranslator;
import com.soffid.iam.sync.engine.extobj.RoleExtensibleObject;
import com.soffid.iam.sync.engine.extobj.UserExtensibleObject;
import com.soffid.iam.sync.engine.extobj.ValueObjectMapper;
import com.soffid.iam.sync.intf.AuthoritativeChange;
import com.soffid.iam.sync.intf.AuthoritativeChangeIdentifier;
import com.soffid.iam.sync.intf.AuthoritativeIdentitySource2;
import com.soffid.iam.sync.intf.ExtensibleObject;
import com.soffid.iam.sync.intf.ExtensibleObjectMapping;
import com.soffid.iam.sync.intf.ExtensibleObjectMgr;
import com.soffid.iam.sync.intf.GroupMgr;
import com.soffid.iam.sync.intf.HostMgr;
import com.soffid.iam.sync.intf.ReconcileMgr2;
import com.soffid.iam.sync.intf.RoleMgr;
import com.soffid.iam.sync.intf.UserMgr;
import es.caib.seycon.util.Base64;
import oracle.jdbc.driver.OracleTypes;

/**
 * Agent to manage relational databases
 * 
 * Parameters:
 * 
 * 0 User name
 * 1 Password
 * 2 JDBC URL
 * 3 Password hash alogithm
 * 4 Password hash prefix
 * 5 Debug
 * 6 Driver type: Oracle / MySQL / PostgreSql / SQLServer
 * <P>
 */

public class SQLAgent extends Agent implements ExtensibleObjectMgr, UserMgr, ReconcileMgr2, RoleMgr, GroupMgr, HostMgr,
	AuthoritativeIdentitySource2 {

	private static final String POSTGRESQL_DRIVER = "postgresql";

	private static final String DB2400_DRIVER = "db2400";

	private static final String DB2_DRIVER = "db2";

	private static final String MYSQL_DRIVER = "mysql";

	private static final String SQLSERVER_DRIVER = "sqlserver";

	private static final String ORACLE_DRIVER = "oracle";

	private static final String INFORMIX_DRIVER = "informix";

	private static final String JTDS_DRIVER = "jtds";

	private static final String ODBC_DRIVER = "odbc";

	ValueObjectMapper vom = new ValueObjectMapper();
	
	ObjectTranslator objectTranslator = null;
	
	private static final long serialVersionUID = 1L;
	boolean debugEnabled;

	String dbUser;
	Password dbPassword;
	String url;

	/** Hash algorithm*/
	MessageDigest digest = null;

	private String hashType;

	private String passwordPrefix;

	protected Collection<ExtensibleObjectMapping> objectMappings;

	private String driver;
	
	static HashMap<String,SQLJDBCPool> pools = new HashMap<String, SQLJDBCPool>();
	
	SQLJDBCPool pool = null;

	private boolean deltaChanges;


	/**
	 * Constructor
	 * 
	 *            </li>
	 */
	public SQLAgent() throws RemoteException {
	}

	@Override
	public void init() throws InternalErrorException {
		log.info("Starting SQL Agent agent on {}", getSystem().getName(),
				null);
		dbUser = getSystem().getParam0();
		dbPassword = getSystem().getParam1() == null ? new Password(""):
			Password.decode(getSystem().getParam1());
		url = getSystem().getParam2();
		
		hashType = getSystem().getParam3();
		passwordPrefix = getSystem().getParam4();
		if (passwordPrefix == null)
			hashType = "{" + hashType + "}";
		String startupSql = getSystem().getParam7();
		deltaChanges = "true".equals(getSystem().getParam8());
		String props = getSystem().getParam9();
		
		debugEnabled = "true".equals(getSystem().getParam5());

		try {
			if (hashType != null && hashType.length() > 0)
				digest = MessageDigest.getInstance(hashType);
		} catch (java.security.NoSuchAlgorithmException e) {
			throw new InternalErrorException(
					"Unable to use SHA encryption algorithm ", e);
		}

		driver = getSystem().getParam6();
		String driverClass = null;
		if (ODBC_DRIVER.equals(driver))
			driverClass = "sun.jdbc.odbc.JdbcOdbcDriver";
		else if (INFORMIX_DRIVER.equals(driver))
			driverClass = "com.informix.jdbc.IfxDriver";
		else if (ORACLE_DRIVER.equals(driver))
			driverClass = "oracle.jdbc.driver.OracleDriver";
		else if (SQLSERVER_DRIVER.equals(driver))
			driverClass = "com.microsoft.sqlserver.jdbc.SQLServerDriver";
		else if (MYSQL_DRIVER.equals(driver))
			driverClass = "com.mysql.jdbc.Driver";
		else if (POSTGRESQL_DRIVER.equals(driver))
			driverClass = "org.postgresql.Driver";
		else if (DB2400_DRIVER.equals(driver))
			driverClass = "com.ibm.as400.access.AS400JDBCDriver";
		else if (DB2_DRIVER.equals(driver))
			driverClass = "com.ibm.db2.jcc.DB2Driver";
		else if (JTDS_DRIVER.equals(driver))
			driverClass = "net.sourceforge.jtds.jdbc.Driver";
		else if (driver != null)
			log.info ("Unknown driver {} ",driver, null);

		try {
        	if (driverClass != null)
        	{
        		log.info ("Registering driver "+driverClass);
	            Class c = Class.forName(driverClass);
	            Driver driver = (java.sql.Driver) c.newInstance();
	            DriverManager.registerDriver(driver);
        		log.info ("Registered driver "+driver.toString());
        	}
        } catch (Exception e) {
            log.info("Error registering driver: {}", e, null);
        }
		pool = pools.get(getAgentName());
		if ( pool == null)
		{
			pool = new SQLJDBCPool();
			pool.setStartupSql(startupSql);
			pools.put(getAgentName(), pool);
		}
		pool.setUrl(url);
		pool.setUser(dbUser);
		pool.setPassword(dbPassword.getPassword());
		if (DB2_DRIVER.equals(driver) && props!=null && !props.trim().isEmpty()) {

			Properties p = new Properties();
			p.put("user", dbUser);
			p.put("password",dbPassword.getPassword());

			// format: p1=v1,p2=v2,etc
			String[] lp = props.split(",");
			for (String sp : lp) {
				String[] i = sp.split("=");
				p.put(i[0], i[1]);
			}

			//p.put("sslConnection", "true");
			pool.setProperties(p);
		}
		try {
			Connection conn = pool.getConnection();
			pool.returnConnection();
		} catch (Exception e) {
			throw new InternalErrorException("Error connecting database", e);
		}
		
		if (deltaChanges) {
			try {
				final AdditionalDataService additionalDataService = new RemoteServiceLocator().getAdditionalDataService();
				if (additionalDataService.findSystemDataType(getAgentName(), DeltaChangesManager.STATUS_ATTRIBUTE) == null) {
					DataType dt = new DataType();
					dt.setCode(DeltaChangesManager.STATUS_ATTRIBUTE);
					dt.setLabel("Previous state data");
					dt.setBuiltin(false);
					dt.setVisibilityExpression("false");
					dt.setType(TypeEnumeration.BINARY_TYPE);
					dt.setUnique(false);
					dt.setRequired(false);
					dt.setSystemName(getAgentName());
					additionalDataService.create(dt);
				}
			} catch (Exception e) {
				throw new InternalErrorException("Error configuring metadata", e);
			}
		}
	}

	/**
	 * Funció per obtindre transformar el password a hash per guardar a la bbdd
	 * 
	 * @param password
	 * @return
	 */
	private String getHashPassword(Password password) {
		String hash = null;
		if (digest == null)
			hash = password.getPassword();
		else
		{
			synchronized (digest) {
				hash = passwordPrefix
						+ Base64.encodeBytes(
								digest.digest(password.getPassword().getBytes()),
								Base64.DONT_BREAK_LINES);
			}
		}
		return hash;
	}

	protected LinkedList<String> getTags (Map<String, String> sentences, String prefix, String objectType)
	{
		LinkedList<String> matches = new LinkedList<String>();
		for (String tag: sentences.keySet())
		{
			if (tag.startsWith(prefix) && sentences.get(tag) != null &&
					sentences.get(tag).trim().length() > 0 )
			{
				if (tag.equals (prefix) || Character.isDigit(tag.charAt(prefix.length())))
					matches.add(tag);
			}
		}
		Collections.sort(matches);
		if (matches.isEmpty())
		{
			log.info("Warning. No SQL sentence found with tag "+prefix);
		}
		return matches;
	}
	
	protected void updateObject(Account acc, ExtensibleObject src, ExtensibleObject obj)
			throws InternalErrorException {
		Map<String, String> properties = objectTranslator.getObjectProperties(obj);
		ExtensibleObject obj2 = obj;
		if (exists (obj, properties, obj.getObjectType()))
		{
			log.info("Exists");
			ExtensibleObject old = select(obj, properties, obj.getObjectType());
			if (acc != null && deltaChanges)
				obj = new DeltaChangesManager(log).merge(acc, old, obj, getServer(), deltaChanges);
			update (src, old, obj, properties, obj.getObjectType());
			log.info("End update");
		}
		else
		{
			log.info("Insert");
			insert (src, obj, properties, obj.getObjectType());
			log.info("End insert");
		}
		if (acc != null && deltaChanges) {
			if (new DeltaChangesManager(log).updateDeltaAttribute(acc, obj2))
			{
				try {
					Method m = getServer().getClass().getMethod("reconcileAccount", Account.class, List.class);
					getServer().reconcileAccount(acc, null);
				} catch (NoSuchMethodException e) {
					try {
						new RemoteServiceLocator().getAccountService().updateAccount2(acc);
					} catch (AccountAlreadyExistsException e1) {
						throw new InternalErrorException("Error updating account snapshot", e1);
					} catch (IOException e1) {
						throw new InternalErrorException("Error updating account snapshot", e1);
					}
				}
			}
		}
	}


	private void insert(ExtensibleObject src, ExtensibleObject obj, Map<String, String> properties, String objectType) throws InternalErrorException {
		debugObject("Creating object", obj, "");
		if (! runTriggers(objectType, SoffidObjectTrigger.PRE_INSERT, null, obj, src))
		{
			return;
		}
		for (String tag: getTags (properties, "insert", objectType))
		{
			String sentence = properties.get(tag);
			executeSentence (sentence, obj);
		}
		runTriggers(objectType, SoffidObjectTrigger.POST_INSERT, null, obj, src);
	}

	protected void delete(ExtensibleObject src, ExtensibleObject obj, Map<String, String> properties, String objectType) throws InternalErrorException {
		debugObject("Removing object", obj, "");
				
		if (! runTriggers(objectType, SoffidObjectTrigger.PRE_DELETE, obj, null, src))
		{
			return;
		}
		for (String tag: getTags (properties, "delete", objectType))
		{
			String sentence = properties.get(tag);
			executeSentence (sentence, obj);
		}
		runTriggers(objectType, SoffidObjectTrigger.POST_DELETE, obj, null, src);
	}

	private void update(ExtensibleObject src, ExtensibleObject old, ExtensibleObject obj, Map<String, String> properties, String objectType) throws InternalErrorException {
		debugObject("Updating object", obj, "");
		if (! runTriggers(objectType, SoffidObjectTrigger.PRE_UPDATE, old, obj, src))
		{
			return;
		}
		for (String tag: getTags (properties, "update", objectType))
		{
			String sentence = properties.get(tag);
			executeSentence (sentence, obj);
		}
		runTriggers(objectType, SoffidObjectTrigger.POST_UPDATE, old, obj, src);
	}

	private boolean exists(ExtensibleObject obj, Map<String, String> properties, String objectType) throws InternalErrorException {
		for (String tag: getTags (properties, "check", objectType))
		{
			String sentence = properties.get(tag);
			String filter = properties.get(tag+"Filter");
			int rows = executeSentence (sentence, obj, filter);
			if (rows > 0)
			{
				if (debugEnabled)
					log.info("Object already exists");
				return true;
			}
		}
		if (debugEnabled)
			log.info("Object does not exist");
		return false;
	}


	private ExtensibleObject select(ExtensibleObject obj, Map<String, String> properties, String objectType) throws InternalErrorException 
	{

		Connection conn;
		try {
			conn = pool.getConnection();
		} catch (Exception e1) {
			throw new InternalErrorException("Error connecting to database ", e1);
		}
		try 
		{
			LinkedList<String> tags = getTags (properties, "select", objectType);
			if (tags.isEmpty())
				tags = getTags (properties, "selectByAccountName", objectType);
			if (tags.isEmpty())
				tags = getTags (properties, "check", objectType);
			for (String tag: tags)
			{
				String sentence = properties.get(tag);
				String filter = properties.get(tag+"Filter");
				List<Object[]> rows = performSelect(conn, sentence, obj, null);
	
				for (int i = 1; i < rows.size(); i++)
				{
					Object[] row = rows.get(i);
					Object[] header = rows.get(0);
					ExtensibleObject resultObject = new ExtensibleObject();
					resultObject.setObjectType( obj.getObjectType() );
					for (int j = 0; j < row.length; j ++)
					{
						String param = header[j].toString();
						if (resultObject.getAttribute(param) == null)
						{
							resultObject.setAttribute(param, row[j]);
						}
					}
					if (passFilter(filter, resultObject, obj))
					{
						return resultObject;
					}
				}
			}
		} catch (SQLException e1) {
			throw new InternalErrorException("Error connecting to database ", e1);
		} finally {
			pool.returnConnection();
		}
		return null;
	}

	private int executeSentence(String sentence, ExtensibleObject obj) throws InternalErrorException {
		return executeSentence(sentence, obj, null);
	}
	
	private int executeSentence(String sentence, ExtensibleObject obj, String filter) throws InternalErrorException {
		return executeSentence(sentence, obj, filter, null);
	}
	
	private int executeSentence(String sentence, ExtensibleObject obj, String filter, List<Map<String, Object>> result) throws InternalErrorException {
		StringBuffer b = new StringBuffer ();
		List<Object> parameters = new LinkedList<Object>();
		if (result != null)
			result.clear();
		
		Object cursor = new Object();
		parseSentence(sentence, obj, b, parameters, cursor);
		
		String parsedSentence = b.toString().trim();
		
		if (debugEnabled)
		{
			log.info("Executing "+parsedSentence);
			for (Object param: parameters)
			{
				log.info("   Param: "+(param == null ? "null": param.toString()+" ["
						+param.getClass().toString()+"]"));
			}
		}
		
		Connection conn;
		try {
			conn = pool.getConnection();
			conn.setAutoCommit(true);
		} catch (Exception e1) {
			throw new InternalErrorException("Error connecting to database ", e1);
		}
		try
		{
		
			if (parsedSentence.toLowerCase().startsWith("select"))
			{
				if (debugEnabled)
					log.info("Getting rows");
				QueryHelper qh = new QueryHelper(conn);
				qh.setEnableNullSqlObject(true);
				try {
					List<Object[]> rows = qh.select(parsedSentence, parameters.toArray());
					log.info("Got rows size = "+rows.size());
					int rowsNumber = 0;
					for (Object[] row: rows)
					{
						if (debugEnabled)
							log.info("Got row ");
						ExtensibleObject eo = new ExtensibleObject();
						eo.setObjectType(obj.getObjectType());
						for (int i = 0; i < row.length; i ++)
						{
							String param = qh.getColumnNames().get(i);
							eo.setAttribute(param, row[i]);
						}
						if (passFilter (filter, eo, obj))
						{
							rowsNumber ++;
							for (int i = 0; i < row.length; i ++)
							{
								String param = qh.getColumnNames().get(i);
								if (obj.getAttribute(param) == null)
								{
									obj.setAttribute(param, row[i]);
								}
							}
							if (result != null)
								result.add(eo);
						}
						else
						{
							if (debugEnabled)
								log.info("Row dows not match filter "+filter);
						}
					}
					if (debugEnabled)
						log.info("Rows number = "+rowsNumber);
					return rowsNumber;
				} catch (SQLException e) {
					throw new InternalErrorException("Error executing sentence "+parsedSentence, e);
				}
			}
			else if (parsedSentence.toLowerCase().startsWith("update") || 
					parsedSentence.toLowerCase().startsWith("delete"))
			{
				QueryHelper qh = new QueryHelper(conn);
				qh.setEnableNullSqlObject(true);
				try {
					return qh.executeUpdate(parsedSentence, parameters.toArray());
				} catch (SQLException e) {
					throw new InternalErrorException("Error executing sentence "+parsedSentence, e);
				}
			} 
			else if (parsedSentence.toLowerCase().startsWith("{call") && ORACLE_DRIVER.equals(driver))
			{
				try {
					List<Object[]> r = executeCall(conn, null, parameters,
							cursor, parsedSentence);
					int rowsNumber = 0;
					Object [] header = null;
					for (Object[] row: r)
					{
						if (header == null)
							header = row;
						else
						{
							ExtensibleObject eo = new ExtensibleObject();
							eo.setObjectType(obj.getObjectType());
							for (int i = 0; i < row.length; i ++)
							{
								String param = header[i].toString();
								eo.setAttribute(param, row[i]);
							}
							if (passFilter (filter, eo, obj))
							{
								rowsNumber ++;
								for (int i = 0; i < row.length; i ++)
								{
									String param = header[i].toString();
									if (obj.getAttribute(param) == null)
									{
										obj.setAttribute(param, row[i]);
									}
								}
								if (result != null)
									result.add(eo);
							}
						}
					}
					return rowsNumber;
				} catch (SQLException e) {
					throw new InternalErrorException("Error executing sentence "+parsedSentence, e);
				}
			}
			else 
			{
				QueryHelper qh = new QueryHelper(conn);
				qh.setEnableNullSqlObject(true);
				try {
					qh.execute(parsedSentence, parameters.toArray());
					return 1;
				} catch (SQLException e) {
					throw new InternalErrorException("Error executing sentence "+parsedSentence, e);
				}
			}
		} finally {
			pool.returnConnection();
		}

	}

	protected boolean passFilter(String filter, ExtensibleObject eo, ExtensibleObject query) throws InternalErrorException {
		if (filter == null || filter.trim().length() == 0)
			return true;
		
		eo.setAttribute("query", query);
		Object obj = objectTranslator.eval(filter, eo);
		if (obj == null || Boolean.FALSE.equals(obj))
			return false;
		else
			return true;
	}

	private void parseSentence(String sentence, ExtensibleObject obj,
			StringBuffer parsedSentence, List<Object> parameters, Object outputCursor) {
		int position = 0;
		// First, transforma sentence into a valid SQL API sentence
		do
		{
			int nextQuote = sentence.indexOf('\'', position);
			int next = sentence.indexOf(':', position);
			if (next < 0)
			{
				parsedSentence.append (sentence.substring(position));
				position = sentence.length();
			}
			else if (nextQuote >= 0 && next > nextQuote)
			{
				parsedSentence.append (sentence.substring(position, nextQuote+1));
				position = nextQuote + 1;
			}
			else
			{
				parsedSentence.append (sentence.substring(position, next));
				int paramStart = next + 1;
				int paramEnd = paramStart;
				while (paramEnd < sentence.length() && 
						Character.isJavaIdentifierPart(sentence.charAt(paramEnd)))
				{
					paramEnd ++;
				}
				if (paramEnd == paramStart) // A := is being used
					parsedSentence.append (":");
				else
				{
					parsedSentence.append ("?");
					String param = sentence.substring(paramStart, paramEnd);
					Object paramValue =  obj.getAttribute(param);
					if (paramValue == null && param.toLowerCase().startsWith("return"))
						parameters.add(outputCursor);
					else
						parameters.add(paramValue);
				}
				position = paramEnd;
			}
		} while (position < sentence.length());
	}

	public void configureMappings(Collection<ExtensibleObjectMapping> objects) throws RemoteException,
			InternalErrorException {
		this.objectMappings  = objects;
		objectTranslator = new ObjectTranslator(getSystem(), getServer(), objectMappings);
		objectTranslator.setObjectFinder(new ExtensibleObjectFinder() {
			
			public ExtensibleObject find(ExtensibleObject pattern) throws Exception {
				log.info("Searching for native object "+pattern.toString());
				return searchObject(pattern);
			}

			public Collection<Map<String,Object>> invoke (String verb, String command, Map<String, Object> params) throws InternalErrorException
			{
				if (debugEnabled)
				{
					log.info ("Invoking: "+verb+" on "+command);
				}

				ExtensibleObject o = new ExtensibleObject();
				if (params != null)
				o.putAll(params);
				if (command == null)
					command = "";
				if (verb != null && !verb.trim().isEmpty())
					command = verb.trim() + " " +command;
				List<Map<String, Object>> result = new LinkedList<Map<String,Object>>();
				executeSentence(command, o, null, result );
				return result;
			}

		});

	}

	protected ExtensibleObject searchObject(ExtensibleObject pattern) throws InternalErrorException {
		debugObject("Searching for object", pattern, "");
		for ( ExtensibleObjectMapping objectMapping: objectMappings)
		{
			if (objectMapping.getSystemObject().equals(pattern.getObjectType()) )
			{
				for (String tag: getTags(objectMapping.getProperties(), "select", objectMapping.getSystemObject()))
				{
					for ( ExtensibleObject obj : selectSystemObjects (pattern, objectMapping, 
							objectMapping.getProperties().get(tag),
							 objectMapping.getProperties().get(tag+"Filter")) )
					{
						debugObject("Got account system object", obj, "");
						return obj;
					}
				}
			}
		}
		return null;
	}


	Date lastModification = null;
	static Date lastCommitedModification = null;
	long lastChangeId = 0;
	HashSet<Long> pendingChanges = new HashSet<Long>();
	
	public Collection<AuthoritativeChange> getChanges()
			throws InternalErrorException {
		
		LinkedList<AuthoritativeChange> changes = new LinkedList<AuthoritativeChange>();
		ExtensibleObject emptyObject = new ExtensibleObject();
		emptyObject.setAttribute("LASTCHANGE", lastCommitedModification);
		
		lastModification = new Date();
		LinkedList<Long> changeIds = new LinkedList<Long>();
		
		Connection conn;
		try {
			conn = pool.getConnection();
		} catch (Exception e1) {
			throw new InternalErrorException("Error connecting to database ", e1);
		}
		try{
			for ( ExtensibleObjectMapping objMapping: objectMappings)
			{
				if (objMapping.getSoffidObject().equals(SoffidObjectType.OBJECT_USER) ||
						objMapping.getSoffidObject().equals(SoffidObjectType.OBJECT_AUTHORITATIVE_CHANGE))
				{
					for (String tag: getTags (objMapping.getProperties(), "selectAll", objMapping.getSystemObject()))
					{
						String filter = objMapping.getProperties().get(tag+"Filter");
						String sentence = objMapping.getProperties().get(tag);
						try {
							List<Object[]> rows = performSelect(conn, sentence, emptyObject, null);
							Object [] header = null;
							for (Object[] row: rows)
							{
								if (header == null)
									header = row;
								else
								{
									ExtensibleObject resultObject = new ExtensibleObject();
									resultObject.setObjectType(objMapping.getSystemObject());
									for (int i = 0; i < row.length; i ++)
									{
										String param = header[i].toString();
										if (resultObject.getAttribute(param) == null)
										{
											resultObject.setAttribute(param, row[i]);
										}
									}
									debugObject("Got authoritative change", resultObject, "");
									if (!passFilter(filter, resultObject, null))
										log.info ("Discarding row");
									else
									{
										ExtensibleObject translated = objectTranslator.parseInputObject(resultObject, objMapping);
										debugObject("Translated to", translated, "");
										AuthoritativeChange ch = new ValueObjectMapper().parseAuthoritativeChange(translated);
										if (ch != null)
										{
											changes.add(ch);
										} else {
											User usuari = new ValueObjectMapper().parseUser(translated);
											if (usuari != null)
											{
												if (debugEnabled && usuari != null)
													log.info ("Result user: "+usuari.toString());
												Long changeId = new Long(lastChangeId++);
												ch = new AuthoritativeChange();
												ch.setId(new AuthoritativeChangeIdentifier());
												ch.getId().setInternalId(changeId);
												ch.setUser(usuari);
												Map<String,Object> attributes = (Map<String, Object>) translated.getAttribute("attributes");
												ch.setAttributes(attributes);
												changes.add(ch);
												changeIds.add(changeId);
											}
										}
									}
								}
							}
						} catch (SQLException e) {
							throw new InternalErrorException("Error executing sentence "+sentence, e);
						}
					}
				}
			}
			pendingChanges.addAll(changeIds);
			return changes;
		} finally {
			pool.returnConnection();
		}
	}

	protected List<Object[]> performSelect(Connection conn,
			String sentence, ExtensibleObject object, Long maxRows) throws SQLException {
		StringBuffer b = new StringBuffer ();
		List<Object> parameters = new LinkedList<Object>();
		Object cursor = new Object();
		
		parseSentence(sentence, object, b, parameters, cursor);
		
		String parsedSentence = b.toString().trim();
		
		if (debugEnabled)
			log.info("Executing "+parsedSentence);
		for (Object param: parameters)
		{
			if (debugEnabled)
				log.info("   Param: "+(param == null ? "null": param.toString()));
		}

		QueryHelper qh = new QueryHelper(conn);
		qh.setEnableNullSqlObject(true);

		if (parsedSentence.toLowerCase().startsWith("{call") && ORACLE_DRIVER.equals(driver))
		{
			
			List<Object[]> result = executeCall(conn, maxRows, parameters,
					cursor, parsedSentence);
			return result;
		}
		else
		{
			List<Object[]> rows = qh.select(parsedSentence, parameters.toArray());
			if (debugEnabled)
				log.info ("Returned "+rows.size()+" rows");
			Object[] header = qh.getColumnNames().toArray(new Object[0]);
			rows.add(0, header);
			return rows;
		}
	}

	private List<Object[]> executeCall(Connection conn, Long maxRows,
			List<Object> parameters, Object cursor, String parsedSentence)
			throws SQLException {
		List<Object[]> result = new LinkedList<Object[]>();
		LinkedList<String> columnNames = new LinkedList<String>();
		CallableStatement stmt = conn.prepareCall(parsedSentence);

		try {
			int num = 0;
			int cursorNumber = -1;
			for (Object param : parameters)
			{
				num++;
				if (param == null)
				{
					stmt.setNull(num, Types.VARCHAR);
				}
				else if (param == cursor)
				{
					stmt.registerOutParameter(num, OracleTypes.CURSOR);
					cursorNumber = num;
				}
				else if (param instanceof Long)
				{
					stmt.setLong(num, (Long) param);
				}
				else if (param instanceof Integer)
				{
					stmt.setInt(num, (Integer) param);
				}
				else if (param instanceof Date)
				{
					stmt.setDate(num, (java.sql.Date) param);
				}
				else if (param instanceof java.sql.Timestamp)
				{
					stmt.setTimestamp(num, (java.sql.Timestamp) param);
				}
				else
				{
					stmt.setString(num, param.toString());
				}
			}
			stmt.execute();
			if (cursorNumber >= 0)
			{
				long rows = 0;
				ResultSet rset = (ResultSet) stmt.getObject(cursorNumber);
				try
				{
					int cols = rset.getMetaData().getColumnCount();
					for (int i = 0; i < cols; i++)
					{
						columnNames.add (rset.getMetaData().getColumnLabel(i+1));
					}
					result.add(columnNames.toArray());
					while (rset.next() && (maxRows == null || rows < maxRows.longValue()))
					{
						rows++;
						Object[] row = new Object[cols];
						for (int i = 0; i < cols; i++)
						{
							Object obj = rset.getObject(i + 1);
							if (obj == null)
							{
								int type = rset.getMetaData().getColumnType(i+1);
								if (type == Types.BINARY ||
									type == Types.LONGVARBINARY ||
									type == Types.VARBINARY || type == Types.BLOB ||
									type == Types.DATE || type == Types.TIMESTAMP ||
									type == Types.TIME || type == Types.BLOB)
										row [i] = new NullSqlObjet(type);
							}
							else if (obj instanceof Date)
							{
								row[i] = rset.getTimestamp(i+1);
							}
							else if (obj instanceof BigDecimal)
							{
								row[i] = rset.getLong(i+1);
							}
							else
								row[i] = obj;
						}
						result.add(row);
					}
				}
				finally
				{
					rset.close();
				}
			}
		}
		finally
		{
			stmt.close();
		}
		return result;
	}

	public void commitChange(AuthoritativeChangeIdentifier id)
			throws InternalErrorException {
		pendingChanges.remove(id.getInternalId());
		if (pendingChanges.isEmpty())
			lastCommitedModification = lastModification;
	}

	public void updateRole(Role role) throws RemoteException,
			InternalErrorException {
		if (!role.getSystem().equals(getSystem().getName()))
			return;
		
		ExtensibleObject soffidObject = new RoleExtensibleObject(role, getServer());

		// First update role
		for ( ExtensibleObjectMapping objectMapping: objectMappings)
		{
			if (objectMapping.getSoffidObject().equals(SoffidObjectType.OBJECT_ROLE))
			{
				ExtensibleObject systemObject = objectTranslator.generateObject(soffidObject, objectMapping);
				updateObject(null, soffidObject, systemObject);
			}
		}
		// Next update role members
				
	}

	protected Collection<? extends ExtensibleObject> selectSystemObjects(
			ExtensibleObject sample, ExtensibleObjectMapping objectMapping, String sentence, String filter) throws InternalErrorException {
		List<ExtensibleObject> result = new LinkedList<ExtensibleObject>();
		
		Connection conn;
		try {
			conn = pool.getConnection();
		} catch (Exception e1) {
			throw new InternalErrorException("Error connecting to database ", e1);
		}
		try 
		{
			try {
				List<Object[]> rows = performSelect(conn, sentence, sample, null);
				Object [] headers = null;
				for (Object[] row: rows)
				{
					if (headers == null)
						headers = row;
					else
					{
						StringBuffer buffer = new StringBuffer();
						ExtensibleObject rowObject = new ExtensibleObject();
						rowObject.setObjectType(objectMapping.getSystemObject());
						for (int i = 0; i < row.length; i ++)
						{
							String param = headers[i].toString();
							rowObject.setAttribute(param, row[i]);
							if (debugEnabled)
							{
								if (i == 0) buffer.append ("ROW: ");
								else buffer.append (", ");
								if (row[i] == null)
									buffer.append ("NULL");
								else
									buffer.append (row[i].toString());
							}
						}
						log.info (buffer.toString());
						if (passFilter(filter, rowObject, sample))
							result.add ( rowObject );
						else if (debugEnabled)
							log.info ("Discarding row");
					}
				}
			} catch (SQLException e) {
				throw new InternalErrorException("Error executing sentence "+sentence, e);
			}
			return result;
		} finally {
			pool.returnConnection();
		}
	}

	public void removeRole(String rolName, String dispatcher)
			throws RemoteException, InternalErrorException {
		Role role  = new Role();
		role.setName(rolName);
		role.setSystem(dispatcher);
		ExtensibleObject soffidObject = new RoleExtensibleObject(role, getServer());

		// First update role
		for ( ExtensibleObjectMapping objectMapping: objectMappings)
		{
			if (objectMapping.getSoffidObject().equals(SoffidObjectType.OBJECT_ROLE))
			{
				ExtensibleObject systemObject = objectTranslator.generateObject(soffidObject, objectMapping);
				delete(soffidObject, systemObject, objectMapping.getProperties(), objectMapping.getSystemObject());
			}
		}
	}

	public List<String> getAccountsList() throws RemoteException,
			InternalErrorException {
		
		ValueObjectMapper vom = new ValueObjectMapper();
		ExtensibleObject sample = new ExtensibleObject();
		List<String> accountNames = new LinkedList<String>();
		// For each mapping
		for ( ExtensibleObjectMapping objectMapping: objectMappings)
		{
			if (objectMapping.getSoffidObject().equals(SoffidObjectType.OBJECT_ACCOUNT))
			{
				for (String tag: getTags(objectMapping.getProperties(), "selectAll", objectMapping.getSystemObject()))
				{
					for ( ExtensibleObject obj : selectSystemObjects (sample, objectMapping, 
							objectMapping.getProperties().get(tag),
							 objectMapping.getProperties().get(tag+"Filter")) )
					{
						debugObject("Got system object", obj, "");
						String accountName = vom.toSingleString(objectTranslator.parseInputAttribute("accountName", obj, objectMapping));
						if (debugEnabled)
							log.info("Account name = "+accountName);
						accountNames.add(accountName);
					}
				}
			}
		}
		
		return accountNames;
	}

	public Account getAccountInfo(String userAccount) throws RemoteException,
			InternalErrorException {
		ValueObjectMapper vom = new ValueObjectMapper();
		Account acc = new Account();
		acc.setName(userAccount);
		acc.setSystem(getAgentName());
		ExtensibleObject sample = new AccountExtensibleObject(acc, getServer());
		// For each mapping
		for ( ExtensibleObjectMapping objectMapping: objectMappings)
		{
			if (objectMapping.getSoffidObject().equals(SoffidObjectType.OBJECT_ACCOUNT) )
			{
				ExtensibleObject translatedSample = objectTranslator.generateObject(sample, objectMapping);
				LinkedList<String> tags = getTags (objectMapping.getProperties(), "select", objectMapping.getSystemObject());
				if (tags.isEmpty())
					tags = getTags (objectMapping.getProperties(), "selectByAccountName", objectMapping.getSystemObject());
				for (String tag: tags)
				{
					for ( ExtensibleObject obj : selectSystemObjects (translatedSample, objectMapping, 
							objectMapping.getProperties().get(tag),
							 objectMapping.getProperties().get(tag+"Filter")) )
					{
						debugObject("Got account system object", obj, "");
						ExtensibleObject soffidObj = objectTranslator.parseInputObject(obj, objectMapping);
						debugObject("Translated account soffid object", soffidObj, "");
						
						if (objectMapping.getSoffidObject().equals(SoffidObjectType.OBJECT_ACCOUNT))
						{
							Account acc2 = vom.parseAccount(soffidObj);
							if (deltaChanges && acc2 != null) {
								try {
									new DeltaChangesManager(log).updateDeltaAttribute(acc2, getAccountGrants(userAccount));
								} catch (InternalErrorException e) {
									throw e;
								} catch (Exception e) {
									throw new InternalErrorException("Error generating current status attribute", e);
								}
							}
							if (debugEnabled)
							{
								log.info("Resulting account: "+acc2.toString());
							}
							return acc2;
						}
						else
						{
							User u = vom.parseUser(soffidObj);
							Account acc2 = vom.parseAccount(soffidObj);
							acc2.setSystem(getAgentName());
							if (acc2.getName() == null)
								acc2.setName(u.getUserName());
							if (acc2.getDescription() == null)
								acc2.setDescription(u.getFullName());
							if (deltaChanges) {
								try {
									new DeltaChangesManager(log).updateDeltaAttribute(acc2, getAccountGrants(userAccount));
								} catch (InternalErrorException e) {
									throw e;
								} catch (Exception e) {
									throw new InternalErrorException("Error generating current status attribute", e);
								}
							}
							if (debugEnabled)
								log.info("Resulting account: "+acc2.toString());
							return acc2;
						}
					}
				}
			}
		}
		
		return null;
	}

	public List<String> getRolesList() throws RemoteException,
			InternalErrorException {
		ValueObjectMapper vom = new ValueObjectMapper();
		ExtensibleObject sample = new ExtensibleObject();
		List<String> roleNames = new LinkedList<String>();
		// For each mapping
		for ( ExtensibleObjectMapping objectMapping: objectMappings)
		{
			if (objectMapping.getSoffidObject().equals(SoffidObjectType.OBJECT_ROLE))
			{
				for (String tag: getTags(objectMapping.getProperties(), "selectAll", objectMapping.getSystemObject()))
				{
					for ( ExtensibleObject obj : selectSystemObjects (sample, objectMapping, 
							objectMapping.getProperties().get(tag),
							 objectMapping.getProperties().get(tag+"Filter")) )
					{
						debugObject("Got role object", obj, "");
						String roleName = vom.toSingleString(objectTranslator.parseInputAttribute("name", obj, objectMapping));
						if (debugEnabled)
							log.info ("Role name = "+roleName);
						roleNames.add(roleName);
					}
				}
			}
		}
		
		return roleNames;
	}

	public Role getRoleFullInfo(String roleName) throws RemoteException,
			InternalErrorException {
		ValueObjectMapper vom = new ValueObjectMapper();
		Role r = new Role();
		r.setName(roleName);
		r.setSystem(getAgentName());
		ExtensibleObject sample = new RoleExtensibleObject(r, getServer());
		// For each mapping
		for ( ExtensibleObjectMapping objectMapping: objectMappings)
		{
			if (objectMapping.getSoffidObject().equals(SoffidObjectType.OBJECT_ROLE))
			{
				ExtensibleObjectMapping eom2 = new ExtensibleObjectMapping(objectMapping);
				eom2.setAttributes(objectMapping.getAttributes());
				eom2.setProperties(objectMapping.getProperties());
				eom2.setCondition(null);
				ExtensibleObject translatedSample = objectTranslator.generateObject(sample, eom2);
				if (translatedSample != null)
				{
					for (String tag: getTags(objectMapping.getProperties(), "select", objectMapping.getSystemObject()))
					{
						for ( ExtensibleObject obj : selectSystemObjects (translatedSample, objectMapping, 
								objectMapping.getProperties().get(tag),
								objectMapping.getProperties().get(tag+"Filter")) )
						{
							debugObject("Got system role object", obj, "");
							ExtensibleObject soffidObj = objectTranslator.parseInputObject(obj, objectMapping);
							debugObject("Translated soffid role object", soffidObj, "");
							return vom.parseRole(soffidObj);
						}
					}
				}
			}
		}
		
		return null;
	}

	public List<RoleGrant> getAccountGrants(String userAccount)
			throws RemoteException, InternalErrorException {
		RoleGrant grant = new RoleGrant();
		grant.setOwnerAccountName(userAccount);
		grant.setSystem(getAgentName());
		grant.setOwnerSystem(getAgentName());
		
		GrantExtensibleObject sample = new GrantExtensibleObject(grant, getServer());
		ValueObjectMapper vom = new ValueObjectMapper();
		List<RoleGrant> result = new LinkedList<RoleGrant>();
		
		// For each mapping
		for ( ExtensibleObjectMapping objectMapping: objectMappings)
		{
			if (objectMapping.getSoffidObject().equals(SoffidObjectType.OBJECT_GRANTED_ROLE) ||
					objectMapping.getSoffidObject().equals(SoffidObjectType.OBJECT_GRANT) ||
					objectMapping.getSoffidObject().equals(SoffidObjectType.OBJECT_ALL_GRANTED_ROLES))
			{
				// First get existing roles
				ExtensibleObject translatedSample = objectTranslator.generateObject(sample, objectMapping, true);
				Collection<? extends ExtensibleObject> existingRoles ;
				for (String tag: getTags(objectMapping.getProperties(), "selectByAccount", objectMapping.getSystemObject()))
				{
					existingRoles = selectSystemObjects (translatedSample, objectMapping, 
							objectMapping.getProperties().get(tag),
							 objectMapping.getProperties().get(tag+"Filter"));
					for (Iterator <? extends ExtensibleObject> objectIterator = existingRoles.iterator();  objectIterator.hasNext();)
					{
						ExtensibleObject object = objectIterator.next ();
						debugObject("Got system grant object", object, null);
						ExtensibleObject soffidObject = objectTranslator.parseInputObject(object, objectMapping);
						debugObject("Translated soffid grant object", soffidObject, null);
						grant = vom.parseGrant(soffidObject);
						if (debugEnabled)
							log.info ("Resulting grant = "+grant.toString());
						result.add (grant);
					}
				}
			}
		}
		return result;
	}

	public void updateUser(Account acc, User userData)
			throws RemoteException, InternalErrorException {
		if (acc == null)
			return;
		
		ExtensibleObject soffidObject = new UserExtensibleObject(acc, userData, getServer());
	

		String password;
		password = getAccountPassword(acc.getName());
		soffidObject.put("password", password);
		// First update role
		boolean found = false;
		for ( ExtensibleObjectMapping objectMapping: objectMappings)
		{
			if (objectMapping.getSoffidObject().equals(SoffidObjectType.OBJECT_USER))
			{
				log.info("Updating user");
				ExtensibleObject systemObject = objectTranslator.generateObject(soffidObject, objectMapping);
				debugObject("Updating user", systemObject, "  ");
				updateObject(acc, soffidObject, systemObject);
				log.info("Done");
				found = true;
			}
		}
		if (! found)
		{
			updateUser(acc);
		} else {
			try {
				// Next update role members
				updateUserRoles (acc, null, 
						getAccountRoles(userData, acc),
						getServer().getAccountExplicitRoles(acc.getName(), getAgentName()));
			} catch (InternalErrorException e) {
				throw e;
			} catch (Exception e) {
				throw new InternalErrorException("Error updating object", e);
			}
		}
	}

	private String getAccountPassword(String accountName)
			throws InternalErrorException {
		String password;
		Password p = getServer().getAccountPassword(accountName, getAgentName());
		if ( p == null)
		{
			p = getServer().generateFakePassword(accountName, getAgentName());
		}
		password = getHashPassword(p);
		return password;
	}
	
	private void updateUserRoles(Account account, User userData, 
			Collection<RoleGrant> allGrants, 
			Collection<RoleGrant> explicitGrants) throws Exception {
		RoleGrant grant = new RoleGrant();
		grant.setOwnerAccountName(account.getName());
		grant.setSystem(getAgentName());
		grant.setOwnerSystem(getAgentName());
		
		ValueObjectMapper vom = new ValueObjectMapper();
		
		// For each mapping
		for ( final ExtensibleObjectMapping objectMapping: objectMappings)
		{
			if (objectMapping.getSoffidObject().equals(SoffidObjectType.OBJECT_GRANTED_ROLE) ||
					objectMapping.getSoffidObject().equals(SoffidObjectType.OBJECT_GRANT) ||
					objectMapping.getSoffidObject().equals(SoffidObjectType.OBJECT_ALL_GRANTED_ROLES))
			{
				ExtensibleObject sample = objectTranslator.generateObject( new GrantExtensibleObject(grant, getServer()), objectMapping);
				// First get existing roles
				boolean foundSelect = false;
				final LinkedList<RoleGrant> existingRoles = new LinkedList<>();
				final LinkedList<ExtensibleObject> existingObjects = new LinkedList<>();
				for (String tag: getTags(objectMapping.getProperties(), "selectByAccount", objectMapping.getSystemObject()))
				{
					for (ExtensibleObject o: selectSystemObjects (sample, objectMapping, 
							objectMapping.getProperties().get(tag),
							 objectMapping.getProperties().get(tag+"Filter")) ) {
						existingObjects.add(o);
						ExtensibleObject soffidObject = objectTranslator.parseInputObject(o, objectMapping);
						final RoleGrant existingGrant = new com.soffid.iam.sync.engine.extobj.ValueObjectMapper().parseGrant(soffidObject);
						if (existingGrant.getRoleName() == null) {
							throw new Exception("Cannot parse row of type "+objectMapping.getSystemObject());
						}
						existingRoles.add( existingGrant );		 
					}
					foundSelect = true;
				}
				if (foundSelect)
				{
					// Now get roles to have
					List<RoleGrant> grants = objectMapping.getSoffidObject().equals(SoffidObjectType.OBJECT_ALL_GRANTED_ROLES)?
							new LinkedList<RoleGrant> (allGrants) :
								new LinkedList<RoleGrant> (explicitGrants);
					new DeltaChangesManager(log).apply(account, existingRoles, grants, getServer(), deltaChanges, new RoleGrantDeltaChangesAction() {
						@Override
						public void remove(RoleGrant currentGrant) throws Exception {
							int pos = existingRoles.indexOf(currentGrant);
							if (pos >= 0) {
								GrantExtensibleObject sourceObject = new GrantExtensibleObject(currentGrant, getServer());
								ExtensibleObject object = existingObjects.get(pos);
								debugObject("Role to revoke: ", object, "");
								delete(sourceObject, object, objectMapping.getProperties(), objectMapping.getSystemObject());
							}
						}
						
						@Override
						public void add(RoleGrant newGrant) throws Exception {
							GrantExtensibleObject sourceObject = new GrantExtensibleObject(newGrant, getServer());
							ExtensibleObject object = objectTranslator.generateObject( sourceObject, objectMapping);
							debugObject("Role to grant: ", object, "");
							updateObject(null, sourceObject, object);
						}
					});
				}
			}
		}
		
	}

	public void updateUser(Account acc)
			throws RemoteException, InternalErrorException {
		ExtensibleObject soffidObject = new AccountExtensibleObject(acc, getServer());
		String password;
		password = getAccountPassword(acc.getName());
		soffidObject.put("password", password);
	
		// First update role
		for ( ExtensibleObjectMapping objectMapping: objectMappings)
		{
			if (objectMapping.getSoffidObject().equals(SoffidObjectType.OBJECT_ACCOUNT))
			{
				ExtensibleObject systemObject = objectTranslator.generateObject(soffidObject, objectMapping);
				updateObject(acc, soffidObject, systemObject);
			}
		}
		// Next update role members
		
		try {
			updateUserRoles (acc, null, getAccountRoles(null, acc),
					getServer().getAccountExplicitRoles(acc.getName(), getAgentName()));
		} catch (InternalErrorException e) {
			throw e;
		} catch (Exception e) {
			throw new InternalErrorException("Error updating object", e);
		}
	}

	public Collection<RoleGrant> getAccountRoles(User user, Account account) throws InternalErrorException, UnknownUserException, IOException {
		Collection<RoleGrant> rg = getServer().getAccountRoles(account.getName(), account.getSystem());
		
		for (RoleGrant grant: rg) {
			grant.setOwnerAccountName(account.getName());
			grant.setOwnerSystem(account.getSystem());
		}
		return rg;
	}

	public void removeUser(String accountName) throws RemoteException,
			InternalErrorException {
		Account acc = getServer().getAccountInfo(accountName, getAgentName());
		if (acc == null)
		{
			acc = new Account();
			acc.setName(accountName);
			acc.setDescription(null);
			acc.setDisabled(true);
			acc.setSystem(getAgentName());
			acc.setStatus(AccountStatus.REMOVED);
			acc.setAttributes(new HashMap<>());
		}
		
		if (acc.getStatus() == AccountStatus.REMOVED)
		{
			ExtensibleObject soffidObject = new AccountExtensibleObject(acc, getServer());
				
			for ( ExtensibleObjectMapping objectMapping: objectMappings)
			{
				if (objectMapping.getSoffidObject().equals(SoffidObjectType.OBJECT_ACCOUNT))
				{
					ExtensibleObject sqlobject = objectTranslator.generateObject(soffidObject, objectMapping);
					delete(soffidObject, sqlobject, objectMapping.getProperties(), objectMapping.getSystemObject());
				}
			}
		} else {
			try {
				User user = getServer().getUserInfo(accountName, getAgentName());
				ExtensibleObject soffidObject = new UserExtensibleObject(acc, user, getServer());
				
				for ( ExtensibleObjectMapping objectMapping: objectMappings)
				{
					if (objectMapping.getSoffidObject().equals(SoffidObjectType.OBJECT_USER))
					{
						ExtensibleObject systemObject = objectTranslator.generateObject(soffidObject, objectMapping);
						updateObject(acc, soffidObject, systemObject);
					}
				}
			} catch (UnknownUserException e) {
				ExtensibleObject soffidObject = new AccountExtensibleObject(acc, getServer());
				
				for ( ExtensibleObjectMapping objectMapping: objectMappings)
				{
					if (objectMapping.getSoffidObject().equals(SoffidObjectType.OBJECT_ACCOUNT))
					{
						ExtensibleObject systemObject = objectTranslator.generateObject(soffidObject, objectMapping);
						updateObject(acc, soffidObject, systemObject);
					}
				}
			}
		}
	}

	public void updateUserPassword(String accountName, User userData,
			Password password, boolean mustchange) throws RemoteException,
			InternalErrorException 
	{

		Account acc = getServer().getAccountInfo(accountName, getAgentName());
		if (acc == null)
			return;
		ExtensibleObject soffidObject = userData == null ?
				new AccountExtensibleObject(acc, getServer()):
				new UserExtensibleObject(acc, userData, getServer());
	
		soffidObject.put("password", getHashPassword(password));
		soffidObject.put("mustChangePassword", mustchange);
	
		// First update role
		for ( ExtensibleObjectMapping objectMapping: objectMappings)
		{
			if (objectMapping.getSoffidObject().equals(SoffidObjectType.OBJECT_ACCOUNT) && userData == null ||
					objectMapping.getSoffidObject().equals(SoffidObjectType.OBJECT_USER) && userData != null)
			{
				ExtensibleObject systemObject = objectTranslator.generateObject(soffidObject, objectMapping);
				Map<String, String> properties = objectTranslator.getObjectProperties(systemObject);
				
				LinkedList<String> updatePasswordTags = getTags(properties, "updatePassword", objectMapping.getSystemObject());
				if (!exists (systemObject, properties, objectMapping.getSystemObject()))
				{
					insert (soffidObject, systemObject, properties, objectMapping.getSystemObject());
				}
				
				if (updatePasswordTags.isEmpty())
				{
					ExtensibleObject oldObject = select(systemObject, properties, systemObject.getObjectType());
					update (soffidObject, oldObject, systemObject, properties, objectMapping.getSystemObject());
				}
				else
				{
					if (! runTriggers(systemObject.getObjectType(), SoffidObjectTrigger.PRE_UPDATE, systemObject, systemObject, soffidObject) ||
							! runTriggers(systemObject.getObjectType(), "preSetPasswod", systemObject, systemObject, soffidObject))
					{
						return;
					}
					for (String s: updatePasswordTags)
					{
						executeSentence(properties.get(s), systemObject);
					}
					runTriggers(systemObject.getObjectType(), SoffidObjectTrigger.POST_UPDATE, systemObject, systemObject, soffidObject);
					runTriggers(systemObject.getObjectType(), "postSetPassword", systemObject, systemObject, soffidObject);
				}
			}
		}
}

	public boolean validateUserPassword(String accountName, Password password)
			throws RemoteException, InternalErrorException {
		Account acc = new Account();
		acc.setName(accountName);
		acc.setSystem(getAgentName());
		ExtensibleObject soffidObject = new UserExtensibleObject(acc, null, getServer());
	
		soffidObject.put("password", getHashPassword(password));
	
		// First update role
		for ( ExtensibleObjectMapping objectMapping: objectMappings)
		{
			if (objectMapping.getSoffidObject().equals(SoffidObjectType.OBJECT_ACCOUNT) ||
					objectMapping.getSoffidObject().equals(SoffidObjectType.OBJECT_USER))
			{
				ExtensibleObject systemObject = objectTranslator.generateObject(soffidObject, objectMapping, true);
				Map<String, String> properties = objectTranslator.getObjectProperties(systemObject);
				
				LinkedList<String> updatePasswordTags = getTags(properties, "validatePassword", objectMapping.getSystemObject());
				for (String s: updatePasswordTags)
				{
					if ( executeSentence(properties.get(s), systemObject) > 0 )
						return true;
				}
			}
		}
		return false;
	}
	
	void debugObject (String msg, Map<String,Object> obj, String indent)
	{
		if (debugEnabled)
		{
			if (indent == null)
				indent = "";
			if (msg != null)
				log.info(indent + msg);
			for (String attribute: obj.keySet())
			{
				Object subObj = obj.get(attribute);
				if (subObj == null)
				{
					log.info (indent+attribute.toString()+": null");
				}
				else if (subObj instanceof Map)
				{
					log.info (indent+attribute.toString()+": Object {");
					debugObject (null, (Map<String, Object>) subObj, indent + "   ");
					log.info (indent+"}");
				}
				else
				{
					log.info (indent+attribute.toString()+": "+subObj.toString());
				}
			}
		}
	}

	public ExtensibleObject getNativeObject(SoffidObjectType type, String object1, String object2)
			throws RemoteException, InternalErrorException {
		return null;
	}

	public ExtensibleObject getSoffidObject(SoffidObjectType type, String object1, String object2)
			throws RemoteException, InternalErrorException {
		return null;
	}
	
	private boolean runTriggers(String objectType, SoffidObjectTrigger triggerType, 
			ExtensibleObject existing, 
			ExtensibleObject obj,
			ExtensibleObject src) throws InternalErrorException {
		return runTriggers(objectType, triggerType.toString(), existing, obj, src);
	}

	private boolean runTriggers(String objectType, String triggerType, 
			ExtensibleObject existing, 
			ExtensibleObject obj,
			ExtensibleObject src) throws InternalErrorException {
		List<ObjectMappingTrigger> triggers = getTriggers (objectType, triggerType);
		for (ObjectMappingTrigger trigger: triggers)
		{
	
			ExtensibleObject eo = new ExtensibleObject();
			eo.setAttribute("source", src);
			eo.setAttribute("newObject", obj);
			eo.setAttribute("oldObject", existing);
			if ( ! objectTranslator.evalExpression(eo, trigger.getScript()) )
			{
				log.info("Trigger "+trigger.getTrigger().toString()+" returned false");
				if (debugEnabled)
				{
					if (existing != null)
						debugObject("old object", existing, "  ");
					if (obj != null)
						debugObject("new object", obj, "  ");
				}
				return false;
			}
		}
		return true;
	}

	private List<ObjectMappingTrigger> getTriggers(String objectType, String type) {
		List<ObjectMappingTrigger> triggers = new LinkedList<ObjectMappingTrigger>();
		for ( ExtensibleObjectMapping objectMapping: objectMappings)
		{
			if (objectMapping.getSystemObject().equals(objectType))
			{
				for ( ObjectMappingTrigger trigger: objectMapping.getTriggers())
				{
					if (trigger.getTrigger().toString().equals(type))
						triggers.add(trigger);
				}
			}
		}
		return triggers;
	}

	public Collection<Map<String, Object>> invoke(String verb, String command,
			Map<String, Object> params) throws RemoteException, InternalErrorException 
	{
		return objectTranslator.getObjectFinder().invoke(verb, command, params);
	}

	public Collection<AuthoritativeChange> getChanges(String lastChange) throws InternalErrorException {
		LinkedList<AuthoritativeChange> changes = new LinkedList<AuthoritativeChange>();
		ExtensibleObject emptyObject = new ExtensibleObject();
		Date d = null;
		if (lastChange != null && !lastChange.trim().isEmpty())
			d = new Date ( Long.parseLong(lastChange));
		lastModification = new Date();
		emptyObject.setAttribute("LASTCHANGE", d);

		if (d == null)
			log.info("Loading complete database");
		else
			log.info("Loading changes since "+lastChange+ "="+ d.toString() );
		Connection conn;
		try {
			conn = pool.getConnection();
		} catch (Exception e1) {
			throw new InternalErrorException("Error connecting to database ", e1);
		}
		try{
			for ( ExtensibleObjectMapping objMapping: objectMappings)
			{
				if (objMapping.getSoffidObject().equals(SoffidObjectType.OBJECT_USER) ||
						objMapping.getSoffidObject().equals(SoffidObjectType.OBJECT_AUTHORITATIVE_CHANGE))
				{
					for (String tag: getTags (objMapping.getProperties(), "selectAll", objMapping.getSystemObject()))
					{
						String filter = objMapping.getProperties().get(tag+"Filter");
						String sentence = objMapping.getProperties().get(tag);
						try {
							List<Object[]> rows = performSelect(conn, sentence, emptyObject, null);
							Object [] header = null;
							for (Object[] row: rows)
							{
								if (header == null)
									header = row;
								else
								{
									ExtensibleObject resultObject = new ExtensibleObject();
									resultObject.setObjectType(objMapping.getSystemObject());
									for (int i = 0; i < row.length; i ++)
									{
										String param = header[i].toString();
										if (resultObject.getAttribute(param) == null)
										{
											resultObject.setAttribute(param, row[i]);
										}
									}
									debugObject("Got authoritative change", resultObject, "");
									if (!passFilter(filter, resultObject, null))
										log.info ("Discarding row");
									else
									{
										ExtensibleObject translated = objectTranslator.parseInputObject(resultObject, objMapping);
										debugObject("Translated to", translated, "");
										AuthoritativeChange ch = new ValueObjectMapper().parseAuthoritativeChange(translated);
										if (ch != null)
										{
											changes.add(ch);
										} else {
											User usuari = new ValueObjectMapper().parseUser(translated);
											if (usuari != null)
											{
												if (debugEnabled && usuari != null)
													log.info ("Result user: "+usuari.toString());
												Long changeId = new Long(lastChangeId++);
												ch = new AuthoritativeChange();
												ch.setId(new AuthoritativeChangeIdentifier());
												ch.getId().setInternalId(changeId);
												ch.setUser(usuari);
												Map<String,Object> attributes = (Map<String, Object>) translated.getAttribute("attributes");
												ch.setAttributes(attributes);
												changes.add(ch);
											}
										}
									}
								}
							}
						} catch (SQLException e) {
							throw new InternalErrorException("Error executing sentence "+sentence, e);
						}
					}
				}
			}
			return changes;
		} finally {
			pool.returnConnection();
		}
	}

	public boolean hasMoreData() throws InternalErrorException {
		return false;
	}

	public String getNextChange() throws InternalErrorException {
		log.info("Setting next change to "+lastModification);
		return Long.toString(lastModification.getTime());
	}

	public List<HostService> getHostServices() throws RemoteException, InternalErrorException {
		return new LinkedList<>();
	}

	@Override
	public void updateHost(Host host) throws RemoteException, InternalErrorException {
		// Next update role members
	}

	@Override
	public void removeHost(String name) throws RemoteException, InternalErrorException {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void updateGroup(Group group) throws RemoteException, InternalErrorException {
		ExtensibleObject soffidObject = new GroupExtensibleObject(group, getSystem().getName(), getServer());

		for ( ExtensibleObjectMapping objectMapping: objectMappings)
		{
			if (objectMapping.getSoffidObject().equals(SoffidObjectType.OBJECT_GROUP))
			{
				ExtensibleObject systemObject = objectTranslator.generateObject(soffidObject, objectMapping);
				updateObject(null, soffidObject, systemObject);
			}
		}
	}

	@Override
	public void removeGroup(String group) throws RemoteException, InternalErrorException {
		Group g = new Group();
		g.setName(group);
		g.setObsolete(true);
		ExtensibleObject soffidObject = new GroupExtensibleObject(g, getSystem().getName(), getServer());
		for ( ExtensibleObjectMapping objectMapping: objectMappings)
		{
			if (objectMapping.getSoffidObject().equals(SoffidObjectType.OBJECT_GROUP))
			{
				ExtensibleObject systemObject = objectTranslator.generateObject(soffidObject, objectMapping);
				delete(soffidObject, systemObject, objectMapping.getProperties(), objectMapping.getSystemObject());
			}
		}
	}
}
	