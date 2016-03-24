package com.soffid.iam.sync.agent;

import java.math.BigDecimal;
import java.rmi.RemoteException;
import java.security.MessageDigest;
import java.sql.CallableStatement;
import java.sql.Connection;
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

import oracle.jdbc.driver.OracleTypes;
import es.caib.seycon.ng.comu.Account;
import es.caib.seycon.ng.comu.Password;
import es.caib.seycon.ng.comu.Rol;
import es.caib.seycon.ng.comu.RolGrant;
import es.caib.seycon.ng.comu.SoffidObjectType;
import es.caib.seycon.ng.comu.Usuari;
import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.ng.exception.UnknownRoleException;
import es.caib.seycon.ng.sync.agent.Agent;
import es.caib.seycon.ng.sync.bootstrap.NullSqlObjet;
import es.caib.seycon.ng.sync.bootstrap.QueryHelper;
import es.caib.seycon.ng.sync.engine.extobj.AccountExtensibleObject;
import es.caib.seycon.ng.sync.engine.extobj.GrantExtensibleObject;
import es.caib.seycon.ng.sync.engine.extobj.ObjectTranslator;
import es.caib.seycon.ng.sync.engine.extobj.RoleExtensibleObject;
import es.caib.seycon.ng.sync.engine.extobj.UserExtensibleObject;
import es.caib.seycon.ng.sync.engine.extobj.ValueObjectMapper;
import es.caib.seycon.ng.sync.engine.pool.JDBCPool;
import es.caib.seycon.ng.sync.intf.AuthoritativeChange;
import es.caib.seycon.ng.sync.intf.AuthoritativeChangeIdentifier;
import es.caib.seycon.ng.sync.intf.AuthoritativeIdentitySource;
import es.caib.seycon.ng.sync.intf.ExtensibleObject;
import es.caib.seycon.ng.sync.intf.ExtensibleObjectMapping;
import es.caib.seycon.ng.sync.intf.ExtensibleObjectMgr;
import es.caib.seycon.ng.sync.intf.ReconcileMgr2;
import es.caib.seycon.ng.sync.intf.RoleMgr;
import es.caib.seycon.ng.sync.intf.UserMgr;
import es.caib.seycon.util.Base64;

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

public class SQLAgent extends Agent implements ExtensibleObjectMgr, UserMgr, ReconcileMgr2, RoleMgr,
	AuthoritativeIdentitySource {

	private static final String POSTGRESQL_DRIVER = "postgresql";

	private static final String MYSQL_DRIVER = "mysql";

	private static final String SQLSERVER_DRIVER = "sqlserver";

	private static final String ORACLE_DRIVER = "oracle";

	private static final String INFORMIX_DRIVER = "informix";

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

	private Collection<ExtensibleObjectMapping> objectMappings;

	private String driver;
	
	static HashMap<String,JDBCPool> pools = new HashMap<String, JDBCPool>();
	
	JDBCPool pool = null;


	/**
	 * Constructor
	 * 
	 *            </li>
	 */
	public SQLAgent() throws RemoteException {
	}

	@Override
	public void init() throws InternalErrorException {
		log.info("Starting SQL Agent agent on {}", getDispatcher().getCodi(),
				null);
		dbUser = getDispatcher().getParam0();
		dbPassword = Password.decode(getDispatcher().getParam1());
		url = getDispatcher().getParam2();
		
		hashType = getDispatcher().getParam3();
		passwordPrefix = getDispatcher().getParam4();
		if (passwordPrefix == null)
			hashType = "{" + hashType + "}";
		
		
		debugEnabled = "true".equals(getDispatcher().getParam5());

		try {
			if (hashType != null && hashType.length() > 0)
				digest = MessageDigest.getInstance(hashType);
		} catch (java.security.NoSuchAlgorithmException e) {
			throw new InternalErrorException(
					"Unable to use SHA encryption algorithm ", e);
		}

		driver = getDispatcher().getParam6();
		String driverClass = null;
		if (INFORMIX_DRIVER.equals(driver))
			driverClass = "com.informix.jdbc.IfxDriver";
		else if (ORACLE_DRIVER.equals(driver))
			driverClass = "oracle.jdbc.driver.OracleDriver";
		else if (SQLSERVER_DRIVER.equals(driver))
			driverClass = "com.microsoft.sqlserver.jdbc.SQLServerDriver";
		else if (MYSQL_DRIVER.equals(driver))
			driverClass = "com.mysql.jdbc.Driver";
		else if (POSTGRESQL_DRIVER.equals(driver))
			driverClass = "org.postgresql.Driver";
			
        try {
        	if (driverClass != null)
        	{
	            Class c = Class.forName(driverClass);
	            DriverManager.registerDriver((java.sql.Driver) c.newInstance());
        	}
        } catch (Exception e) {
            log.info("Error registering driver: {}", e, null);
        }
		pool = pools.get(getCodi());
		if ( pool == null)
		{
			pool = new JDBCPool();
			pools.put(getCodi(), pool);
		}
        pool.setUrl(url);
        pool.setPassword(dbPassword.getPassword());
        pool.setUser(dbUser);
		try {
			Connection conn = pool.getConnection();
			pool.returnConnection();
		} catch (Exception e) {
			throw new InternalErrorException("Error connecting database", e);
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

	private LinkedList<String> getTags (Map<String, String> sentences, String prefix)
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
		return matches;
	}
	
	private void updateObject(ExtensibleObject obj)
			throws InternalErrorException {
		Map<String, String> properties = objectTranslator.getObjectProperties(obj);
		if (exists (obj, properties))
		{
			update (obj, properties);
		}
		else
		{
			insert (obj, properties);
		}
	}


	private void insert(ExtensibleObject obj, Map<String, String> properties) throws InternalErrorException {
		debugObject("Creating object", obj, "");
		for (String tag: getTags (properties, "insert"))
		{
			String sentence = properties.get(tag);
			executeSentence (sentence, obj);
		}
	}

	private void delete(ExtensibleObject obj, Map<String, String> properties) throws InternalErrorException {
		debugObject("Removing object", obj, "");
		for (String tag: getTags (properties, "delete"))
		{
			String sentence = properties.get(tag);
			executeSentence (sentence, obj);
		}
	}

	private void update(ExtensibleObject obj, Map<String, String> properties) throws InternalErrorException {
		debugObject("Updating object", obj, "");
		for (String tag: getTags (properties, "update"))
		{
			String sentence = properties.get(tag);
			executeSentence (sentence, obj);
		}
	}

	private boolean exists(ExtensibleObject obj, Map<String, String> properties) throws InternalErrorException {
		for (String tag: getTags (properties, "check"))
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

	private int executeSentence(String sentence, ExtensibleObject obj) throws InternalErrorException {
		return executeSentence(sentence, obj, null);
	}
	
	private int executeSentence(String sentence, ExtensibleObject obj, String filter) throws InternalErrorException {
		StringBuffer b = new StringBuffer ();
		List<Object> parameters = new LinkedList<Object>();

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
					List<Object[]> result = executeCall(conn, null, parameters,
							cursor, parsedSentence);
					int rowsNumber = 0;
					Object [] header = null;
					for (Object[] row: result)
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

	private boolean passFilter(String filter, ExtensibleObject eo, ExtensibleObject query) throws InternalErrorException {
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
		objectTranslator = new ObjectTranslator(getDispatcher(), getServer(), objectMappings);
		
	}

	Date lastModification = null;
	Date lastCommitedModification = null;
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
					for (String tag: getTags (objMapping.getProperties(), "selectAll"))
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
											Usuari usuari = new ValueObjectMapper().parseUsuari(translated);
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

	private List<Object[]> performSelect(Connection conn,
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

	public void updateRole(Rol role) throws RemoteException,
			InternalErrorException {
		if (!role.getBaseDeDades().equals(getDispatcher().getCodi()))
			return;
		
		ExtensibleObject soffidObject = new RoleExtensibleObject(role, getServer());

		// First update role
		for ( ExtensibleObjectMapping objectMapping: objectMappings)
		{
			if (objectMapping.getSoffidObject().equals(SoffidObjectType.OBJECT_ROLE))
			{
				ExtensibleObject systemObject = objectTranslator.generateObject(soffidObject, objectMapping);
				updateObject(systemObject);
			}
		}
		// Next update role members
		
		try {
			updateRoleMembers (role, getServer().getRoleAccounts(role.getId(), getDispatcher().getCodi()));
		} catch (UnknownRoleException e) {
			throw new InternalErrorException("Error updating role", e);
		}
	}

	private void updateRoleMembers(Rol role, Collection<Account> initialGrants) throws InternalErrorException {
		RolGrant grant = new RolGrant();
		grant.setRolName(role.getNom());
		grant.setDispatcher(role.getBaseDeDades());
		grant.setOwnerDispatcher(role.getBaseDeDades());
		
		GrantExtensibleObject sample = new GrantExtensibleObject(grant, getServer());
		ValueObjectMapper vom = new ValueObjectMapper();
		
		// For each mapping
		for ( ExtensibleObjectMapping objectMapping: objectMappings)
		{
			if (objectMapping.getSoffidObject().equals(SoffidObjectType.OBJECT_GRANTED_ROLE) ||
					objectMapping.getSoffidObject().equals(SoffidObjectType.OBJECT_ALL_GRANTED_ROLES))
			{
				// First get existing roles
				LinkedList<ExtensibleObject> existingRoles = new LinkedList<ExtensibleObject>();
				boolean foundSelect = false;
				for (String tag: getTags(objectMapping.getProperties(), "selectByRole"))
				{
					existingRoles.addAll ( selectSystemObjects (sample, objectMapping, 
							objectMapping.getProperties().get(tag),
							 objectMapping.getProperties().get(tag+"Filter")) );
					foundSelect = true;
				}
				if (foundSelect)
				{
					// Now get roles to have
					Collection<Account> grants = new LinkedList<Account> (initialGrants);
					// Now add non existing roles
					for (Iterator<Account> accountIterator = grants.iterator(); accountIterator.hasNext(); )
					{
						Account account = accountIterator.next();
						
						// Check if this account is already granted
						boolean found = false;
						for (Iterator <ExtensibleObject> objectIterator = existingRoles.iterator(); ! found && objectIterator.hasNext();)
						{
							ExtensibleObject object = objectIterator.next ();
							String accountName = vom.toSingleString(objectTranslator.parseInputAttribute("ownerAccount", object, objectMapping));
							if (accountName != null && accountName.equals (account.getName()))
							{
								objectIterator.remove();
								found = true;
							}
						}
						if (! found)
						{
							RolGrant rg = new RolGrant();
							rg.setOwnerAccountName(account.getName());
							rg.setOwnerDispatcher(account.getDispatcher());
							rg.setRolName(role.getNom());
							rg.setDispatcher(role.getBaseDeDades());
							ExtensibleObject object = objectTranslator.generateObject( new GrantExtensibleObject(rg, getServer()), objectMapping);
							updateObject(object);
						}
					}
					// Now remove unneeded grants
					for (Iterator <ExtensibleObject> objectIterator = existingRoles.iterator(); objectIterator.hasNext();)
					{
						ExtensibleObject object = objectIterator.next ();
						delete(object, objectMapping.getProperties());
					}
				}
			}
		}
		
	}

	private Collection<? extends ExtensibleObject> selectSystemObjects(
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
		Rol role  = new Rol();
		role.setNom(rolName);
		role.setBaseDeDades(dispatcher);
		ExtensibleObject soffidObject = new RoleExtensibleObject(role, getServer());

		// First update role
		for ( ExtensibleObjectMapping objectMapping: objectMappings)
		{
			if (objectMapping.getSoffidObject().equals(SoffidObjectType.OBJECT_ROLE))
			{
				ExtensibleObject systemObject = objectTranslator.generateObject(soffidObject, objectMapping);
				delete(systemObject, objectMapping.getProperties());
			}
		}
		// Next remove role members
		Collection<Account> emptyList = Collections.emptyList();
		updateRoleMembers (role, emptyList);
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
				for (String tag: getTags(objectMapping.getProperties(), "selectAll"))
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
		acc.setDispatcher(getCodi());
		ExtensibleObject sample = new AccountExtensibleObject(acc, getServer());
		// For each mapping
		for ( ExtensibleObjectMapping objectMapping: objectMappings)
		{
			if (objectMapping.getSoffidObject().equals(SoffidObjectType.OBJECT_ACCOUNT) )
			{
				ExtensibleObject translatedSample = objectTranslator.generateObject(sample, objectMapping);
				for (String tag: getTags(objectMapping.getProperties(), "selectByAccountName"))
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
							if (debugEnabled)
							{
								log.info("Resulting account: "+acc2.toString());
							}
							return acc2;
						}
						else
						{
							Usuari u = vom.parseUsuari(soffidObj);
							Account acc2 = vom.parseAccount(soffidObj);
							acc2.setDispatcher(getCodi());
							if (acc2.getName() == null)
								acc2.setName(u.getCodi());
							if (acc2.getDescription() == null)
								acc2.setDescription(u.getFullName());
							if (acc2.getDescription() == null)
								acc2.setDescription(u.getNom()+" "+u.getPrimerLlinatge());
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
				for (String tag: getTags(objectMapping.getProperties(), "selectAll"))
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

	public Rol getRoleFullInfo(String roleName) throws RemoteException,
			InternalErrorException {
		ValueObjectMapper vom = new ValueObjectMapper();
		Rol r = new Rol();
		r.setNom(roleName);
		r.setBaseDeDades(getCodi());
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
					for (String tag: getTags(objectMapping.getProperties(), "selectByName"))
					{
						for ( ExtensibleObject obj : selectSystemObjects (translatedSample, objectMapping, 
								objectMapping.getProperties().get(tag),
								objectMapping.getProperties().get(tag+"Filter")) )
						{
							debugObject("Got system role object", obj, "");
							ExtensibleObject soffidObj = objectTranslator.parseInputObject(obj, objectMapping);
							debugObject("Translated soffid role object", soffidObj, "");
							return vom.parseRol(soffidObj);
						}
					}
				}
			}
		}
		
		return null;
	}

	public List<RolGrant> getAccountGrants(String userAccount)
			throws RemoteException, InternalErrorException {
		RolGrant grant = new RolGrant();
		grant.setOwnerAccountName(userAccount);
		grant.setDispatcher(getCodi());
		grant.setOwnerDispatcher(getCodi());
		
		GrantExtensibleObject sample = new GrantExtensibleObject(grant, getServer());
		ValueObjectMapper vom = new ValueObjectMapper();
		List<RolGrant> result = new LinkedList<RolGrant>();
		
		// For each mapping
		for ( ExtensibleObjectMapping objectMapping: objectMappings)
		{
			if (objectMapping.getSoffidObject().equals(SoffidObjectType.OBJECT_GRANTED_ROLE) ||
					objectMapping.getSoffidObject().equals(SoffidObjectType.OBJECT_ALL_GRANTED_ROLES))
			{
				// First get existing roles
				ExtensibleObject translatedSample = objectTranslator.generateObject(sample, objectMapping, true);
				Collection<? extends ExtensibleObject> existingRoles ;
				for (String tag: getTags(objectMapping.getProperties(), "selectByAccount"))
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

	public void updateUser(String accountName, Usuari userData)
			throws RemoteException, InternalErrorException {
		Account acc = getServer().getAccountInfo(accountName, getDispatcher().getCodi());
		ExtensibleObject soffidObject = new UserExtensibleObject(acc, userData, getServer());
	

		String password;
		password = getAccountPassword(accountName);
		soffidObject.put("password", password);
		// First update role
		for ( ExtensibleObjectMapping objectMapping: objectMappings)
		{
			if (objectMapping.getSoffidObject().equals(SoffidObjectType.OBJECT_USER))
			{
				ExtensibleObject systemObject = objectTranslator.generateObject(soffidObject, objectMapping);
				updateObject(systemObject);
			}
		}
		// Next update role members
		
		updateUserRoles (accountName, null, 
				getServer().getAccountRoles(accountName, getCodi()),
				getServer().getAccountExplicitRoles(accountName, getCodi()));
	}

	private String getAccountPassword(String accountName)
			throws InternalErrorException {
		String password;
		Password p = getServer().getAccountPassword(accountName, getCodi());
		if ( p == null)
		{
			p = getServer().generateFakePassword(accountName, getCodi());
		}
		password = getHashPassword(p);
		return password;
	}
	
	private void updateUserRoles(String accountName, Usuari userData, 
			Collection<RolGrant> allGrants, 
			Collection<RolGrant> explicitGrants) throws InternalErrorException {
		RolGrant grant = new RolGrant();
		grant.setOwnerAccountName(accountName);
		grant.setDispatcher(getCodi());
		grant.setOwnerDispatcher(getCodi());
		
		ValueObjectMapper vom = new ValueObjectMapper();
		
		// For each mapping
		for ( ExtensibleObjectMapping objectMapping: objectMappings)
		{
			if (objectMapping.getSoffidObject().equals(SoffidObjectType.OBJECT_GRANTED_ROLE) ||
					objectMapping.getSoffidObject().equals(SoffidObjectType.OBJECT_GRANT) ||
					objectMapping.getSoffidObject().equals(SoffidObjectType.OBJECT_ALL_GRANTED_ROLES))
			{
				ExtensibleObject sample = objectTranslator.generateObject( new GrantExtensibleObject(grant, getServer()), objectMapping);
				// First get existing roles
				LinkedList<ExtensibleObject> existingRoles = new LinkedList<ExtensibleObject>();
				boolean foundSelect = false;
				for (String tag: getTags(objectMapping.getProperties(), "selectByAccount"))
				{
					existingRoles.addAll ( selectSystemObjects (sample, objectMapping, 
							objectMapping.getProperties().get(tag),
							 objectMapping.getProperties().get(tag+"Filter")) );
					foundSelect = true;
				}
				if (foundSelect)
				{
					// Now get roles to have
					Collection<RolGrant> grants = objectMapping.getSoffidObject().equals(SoffidObjectType.OBJECT_ALL_GRANTED_ROLES)?
							new LinkedList<RolGrant> (allGrants) :
								new LinkedList<RolGrant> (explicitGrants);
					// Now add non existing roles
					for (Iterator<RolGrant> grantIterator = grants.iterator(); grantIterator.hasNext(); )
					{
						RolGrant newGrant = grantIterator.next();
						
						if (debugEnabled)
							log.info ("Testing rol grant "+newGrant);
						
						// Check if this account is already granted
						boolean found = false;
						for (Iterator <ExtensibleObject> objectIterator = existingRoles.iterator(); ! found && objectIterator.hasNext();)
						{
							ExtensibleObject object = objectIterator.next ();
							String roleName = vom.toSingleString(objectTranslator.parseInputAttribute("grantedRole", object, objectMapping));
							if (roleName != null && roleName.equals (newGrant.getRolName()))
							{
								String domainValue = vom.toSingleString(objectTranslator.parseInputAttribute("domainValue", object, objectMapping));
								if (domainValue == null && newGrant.getDomainValue() == null ||
										newGrant.getDomainValue() != null && newGrant.getDomainValue().equals(domainValue))
								{
									objectIterator.remove();
									if (debugEnabled)
										debugObject("Found rol grant "+newGrant+": ", object, "");
									found = true;
								}
							}
						}
						if (! found)
						{
							newGrant.setOwnerAccountName(accountName);
							newGrant.setOwnerDispatcher(getCodi());
							ExtensibleObject object = objectTranslator.generateObject( new GrantExtensibleObject(newGrant, getServer()), objectMapping);
							debugObject("Role to grant: ", object, "");
							updateObject(object);
						}
					}
					// Now remove unneeded grants
					for (Iterator <ExtensibleObject> objectIterator = existingRoles.iterator(); objectIterator.hasNext();)
					{
						ExtensibleObject object = objectIterator.next ();
						debugObject("Role to revoke: ", object, "");
						delete(object, objectMapping.getProperties());
					}
				}
			}
		}
		
	}

	public void updateUser(String accountName, String description)
			throws RemoteException, InternalErrorException {
		Account acc = getServer().getAccountInfo(accountName, getCodi());
		ExtensibleObject soffidObject = new AccountExtensibleObject(acc, getServer());
		String password;
		password = getAccountPassword(accountName);
		soffidObject.put("password", password);
	
		// First update role
		for ( ExtensibleObjectMapping objectMapping: objectMappings)
		{
			if (objectMapping.getSoffidObject().equals(SoffidObjectType.OBJECT_ACCOUNT))
			{
				ExtensibleObject systemObject = objectTranslator.generateObject(soffidObject, objectMapping);
				updateObject(systemObject);
			}
		}
		// Next update role members
		
		updateUserRoles (accountName, null, getServer().getAccountRoles(accountName, getCodi()),
				getServer().getAccountExplicitRoles(accountName, getCodi()));
	}

	public void removeUser(String accountName) throws RemoteException,
			InternalErrorException {
		Account acc = new Account();
		acc.setName(accountName);
		acc.setDescription(null);
		acc.setDisabled(true);
		acc.setDispatcher(getCodi());
		ExtensibleObject soffidObject = new AccountExtensibleObject(acc, getServer());
		
		// First update role
		for ( ExtensibleObjectMapping objectMapping: objectMappings)
		{
			if (objectMapping.getSoffidObject().equals(SoffidObjectType.OBJECT_ACCOUNT))
			{
				ExtensibleObject sqlobject = objectTranslator.generateObject(soffidObject, objectMapping);
				delete(sqlobject, objectMapping.getProperties());
			}
		}
	}

	public void updateUserPassword(String accountName, Usuari userData,
			Password password, boolean mustchange) throws RemoteException,
			InternalErrorException 
	{

		Account acc = new Account();
		acc.setName(accountName);
		acc.setDescription(userData.getFullName());
		acc.setDispatcher(getCodi());
		ExtensibleObject soffidObject = new UserExtensibleObject(acc, userData, getServer());
	
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
				
				LinkedList<String> updatePasswordTags = getTags(properties, "updatePassword");
				if (!exists (systemObject, properties))
				{
					insert (systemObject, properties);
				}
				
				if (updatePasswordTags.isEmpty())
					update (systemObject, properties);
				else
				{
					for (String s: updatePasswordTags)
					{
						executeSentence(properties.get(s), systemObject);
					}
				}
			}
		}
}

	public boolean validateUserPassword(String accountName, Password password)
			throws RemoteException, InternalErrorException {
		Account acc = new Account();
		acc.setName(accountName);
		acc.setDispatcher(getCodi());
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
				
				LinkedList<String> updatePasswordTags = getTags(properties, "validatePassword");
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
}
	