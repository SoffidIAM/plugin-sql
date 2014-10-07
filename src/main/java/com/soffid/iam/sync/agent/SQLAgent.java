package com.soffid.iam.sync.agent;

import java.io.UnsupportedEncodingException;
import java.rmi.RemoteException;
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Vector;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.ejb.RemoveException;

import com.informix.jdbc.IfxDriver;
import com.mysql.jdbc.Driver;
import com.soffid.iam.api.Group;
import com.soffid.iam.api.RoleGrant;

import es.caib.seycon.ng.comu.Account;
import es.caib.seycon.ng.comu.AttributeDirection;
import es.caib.seycon.ng.comu.AttributeMapping;
import es.caib.seycon.ng.comu.DadaUsuari;
import es.caib.seycon.ng.comu.Dispatcher;
import es.caib.seycon.ng.comu.Grup;
import es.caib.seycon.ng.comu.LlistaCorreu;
import es.caib.seycon.ng.comu.ObjectMapping;
import es.caib.seycon.ng.comu.Password;
import es.caib.seycon.ng.comu.Rol;
import es.caib.seycon.ng.comu.RolGrant;
import es.caib.seycon.ng.comu.SoffidObjectType;
import es.caib.seycon.ng.comu.Usuari;
import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.ng.exception.UnknownRoleException;
import es.caib.seycon.ng.exception.UnknownUserException;
import es.caib.seycon.ng.sync.agent.Agent;
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
import es.caib.seycon.ng.sync.intf.ExtensibleObjects;
import es.caib.seycon.ng.sync.intf.ReconcileMgr;
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
	
	static JDBCPool pool = new JDBCPool();


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
		
		hashType = getDispatcher().getParam4();
		passwordPrefix = getDispatcher().getParam5();
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
			executeSentence (sentence, obj, null);
		}
	}

	private void delete(ExtensibleObject obj, Map<String, String> properties) throws InternalErrorException {
		debugObject("Removing object", obj, "");
		for (String tag: getTags (properties, "delete"))
		{
			String sentence = properties.get(tag);
			executeSentence (sentence, obj, null);
		}
	}

	private void update(ExtensibleObject obj, Map<String, String> properties) throws InternalErrorException {
		debugObject("Updating object", obj, "");
		for (String tag: getTags (properties, "update"))
		{
			String sentence = properties.get(tag);
			executeSentence (sentence, obj, null);
		}
	}

	private boolean exists(ExtensibleObject obj, Map<String, String> properties) throws InternalErrorException {
		for (String tag: getTags (properties, "check"))
		{
			String sentence = properties.get(tag);
			int rows = executeSentence (sentence, obj, null);
			if (rows > 0)
				return true;
		}
		return false;
	}

	private int executeSentence(String sentence, ExtensibleObject obj, List<Object[]> result) throws InternalErrorException {
		StringBuffer b = new StringBuffer ();
		List<Object> parameters = new LinkedList<Object>();
		
		parseSentence(sentence, obj, b, parameters);
		
		String parsedSentence = b.toString().trim();
		
		if (debugEnabled)
		{
			log.info("Executing "+parsedSentence);
			for (Object param: parameters)
			{
				log.info("   Param: "+(param == null ? "null": param.toString()));
			}
		}
		
		Connection conn;
		try {
			conn = pool.getConnection();
		} catch (Exception e1) {
			throw new InternalErrorException("Error connecting to database ", e1);
		}
		try
		{
		
			if (parsedSentence.toLowerCase().startsWith("select"))
			{
				QueryHelper qh = new QueryHelper(conn);
				qh.setEnableNullSqlObject(true);
				try {
					List<Object[]> rows = qh.select(parsedSentence, parameters.toArray());
					for (Object[] row: rows)
					{
						for (int i = 0; i < row.length; i ++)
						{
							String param = qh.getColumnNames().get(i);
							if (obj.getAttribute(param) == null)
							{
								obj.setAttribute(param, row[i]);
							}
						}
					}
					return rows.size();
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

	private void parseSentence(String sentence, ExtensibleObject obj,
			StringBuffer parsedSentence, List<Object> parameters) {
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
				parsedSentence.append ("?");
				int paramStart = next + 1;
				int paramEnd = paramStart;
				while (paramEnd < sentence.length() && 
						Character.isJavaIdentifierPart(sentence.charAt(paramEnd)))
				{
					paramEnd ++;
				}
				String param = sentence.substring(paramStart, paramEnd);
				parameters.add(obj.getAttribute(param));
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
				if (objMapping.getSoffidObject().equals(SoffidObjectType.OBJECT_USER))
				{
					for (String tag: getTags (objMapping.getProperties(), "selectAll"))
					{
						String sentence = objMapping.getProperties().get(tag);
						StringBuffer b = new StringBuffer ();
						List<Object> parameters = new LinkedList<Object>();
						
						parseSentence(sentence, emptyObject, b, parameters);
						
						String parsedSentence = b.toString().trim();
						
						QueryHelper qh = new QueryHelper(conn);
						qh.setEnableNullSqlObject(true);
						try {
							List<Object[]> rows = qh.select(parsedSentence, parameters.toArray());
							for (Object[] row: rows)
							{
								ExtensibleObject resultObject = new ExtensibleObject();
								resultObject.setObjectType(objMapping.getSystemObject());
								for (int i = 0; i < row.length; i ++)
								{
									String param = qh.getColumnNames().get(i);
									if (resultObject.getAttribute(param) == null)
									{
										resultObject.setAttribute(param, row[i]);
									}
								}
								debugObject("Got authoritative change", resultObject, "");
								ExtensibleObject translated = objectTranslator.parseInputObject(resultObject, objMapping);
								debugObject("Translated to", translated, "");
								Usuari usuari = new ValueObjectMapper().parseUsuari(translated);
								if (usuari != null)
								{
									if (debugEnabled && usuari != null)
										log.info ("Result user: "+usuari.toString());
									Long changeId = new Long(lastChangeId++);
									AuthoritativeChange ch = new AuthoritativeChange();
									ch.setId(new AuthoritativeChangeIdentifier());
									ch.getId().setInternalId(changeId);
									ch.setUser(usuari);
									Map<String,Object> attributes = (Map<String, Object>) translated.getAttribute("attributes");
									ch.setAttributes(attributes);
									changes.add(ch);
									changeIds.add(changeId);
								}
							}
						} catch (SQLException e) {
							throw new InternalErrorException("Error executing sentence "+parsedSentence, e);
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

	public void commitChange(AuthoritativeChangeIdentifier id)
			throws InternalErrorException {
		pendingChanges.remove(id.getInternalId());
		if (pendingChanges.isEmpty())
			lastCommitedModification = lastModification;
	}

	public void updateRole(Rol role) throws RemoteException,
			InternalErrorException {
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
					existingRoles.addAll ( selectSystemObjects (sample, objectMapping, objectMapping.getProperties().get(tag)) );
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
			ExtensibleObject sample, ExtensibleObjectMapping objectMapping, String sentence) throws InternalErrorException {
		StringBuffer b = new StringBuffer ();
		List<Object> parameters = new LinkedList<Object>();
		List<ExtensibleObject> result = new LinkedList<ExtensibleObject>();
		
		parseSentence(sentence, sample, b, parameters);
		
		String parsedSentence = b.toString().trim();
		
		Connection conn;
		try {
			conn = pool.getConnection();
		} catch (Exception e1) {
			throw new InternalErrorException("Error connecting to database ", e1);
		}
		try 
		{
			QueryHelper qh = new QueryHelper(conn);
			qh.setEnableNullSqlObject(true);
			try {
				log.info("Executing "+parsedSentence);
				for (Object param: parameters)
				{
					log.info("   Param: "+(param == null ? "null": param.toString()));
				}
	
				List<Object[]> rows = qh.select(parsedSentence, parameters.toArray());
				for (Object[] row: rows)
				{
					ExtensibleObject rowObject = new ExtensibleObject();
					rowObject.setObjectType(objectMapping.getSystemObject());
					for (int i = 0; i < row.length; i ++)
					{
						String param = qh.getColumnNames().get(i);
						rowObject.setAttribute(param, row[i]);
					}
					
					result.add ( rowObject );
					
				}
			} catch (SQLException e) {
				throw new InternalErrorException("Error executing sentence "+parsedSentence, e);
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
					for ( ExtensibleObject obj : selectSystemObjects (sample, objectMapping, objectMapping.getProperties().get(tag)) )
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
			if (objectMapping.getSoffidObject().equals(SoffidObjectType.OBJECT_ACCOUNT) || 
					objectMapping.getSoffidObject().equals(SoffidObjectType.OBJECT_USER))
			{
				ExtensibleObject translatedSample = objectTranslator.generateObject(sample, objectMapping);
				for (String tag: getTags(objectMapping.getProperties(), "selectByAccountName"))
				{
					for ( ExtensibleObject obj : selectSystemObjects (translatedSample, objectMapping, objectMapping.getProperties().get(tag)) )
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
					for ( ExtensibleObject obj : selectSystemObjects (sample, objectMapping, objectMapping.getProperties().get(tag)) )
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
				ExtensibleObject translatedSample = objectTranslator.generateObject(sample, objectMapping);
				for (String tag: getTags(objectMapping.getProperties(), "selectByName"))
				{
					for ( ExtensibleObject obj : selectSystemObjects (translatedSample, objectMapping, objectMapping.getProperties().get(tag)) )
					{
						debugObject("Got system role object", obj, "");
						ExtensibleObject soffidObj = objectTranslator.parseInputObject(obj, objectMapping);
						debugObject("Translated soffid role object", soffidObj, "");
						return vom.parseRol(soffidObj);
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
				ExtensibleObject translatedSample = objectTranslator.generateObject(sample, objectMapping);
				Collection<? extends ExtensibleObject> existingRoles ;
				for (String tag: getTags(objectMapping.getProperties(), "selectByAccount"))
				{
					existingRoles = selectSystemObjects (translatedSample, objectMapping, objectMapping.getProperties().get(tag));
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
		Account acc = new Account();
		acc.setName(accountName);
		acc.setDescription(userData.getFullName());
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
		
		updateUserRoles (accountName, null, getServer().getAccountRoles(accountName, getCodi()));
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
	
	private void updateUserRoles(String accountName, Usuari userData, Collection<RolGrant> initialGrants) throws InternalErrorException {
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
					existingRoles.addAll ( selectSystemObjects (sample, objectMapping, objectMapping.getProperties().get(tag)) );
					foundSelect = true;
				}
				if (foundSelect)
				{
					// Now get roles to have
					Collection<RolGrant> grants = new LinkedList<RolGrant> (initialGrants);
					// Now add non existing roles
					for (Iterator<RolGrant> grantIterator = grants.iterator(); grantIterator.hasNext(); )
					{
						RolGrant newGrant = grantIterator.next();
						
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
									found = true;
								}
							}
						}
						if (! found)
						{
							newGrant.setOwnerAccountName(accountName);
							newGrant.setOwnerDispatcher(getCodi());
							ExtensibleObject object = objectTranslator.generateObject( new GrantExtensibleObject(newGrant, getServer()), objectMapping);
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

	public void updateUser(String accountName, String description)
			throws RemoteException, InternalErrorException {
		Account acc = new Account();
		acc.setName(accountName);
		acc.setDescription(description);
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
		
		updateUserRoles (accountName, null, getServer().getAccountRoles(accountName, getCodi()));
	}

	public void removeUser(String accountName) throws RemoteException,
			InternalErrorException {
		Account acc = new Account();
		acc.setName(accountName);
		acc.setDescription(null);
		acc.setDisabled(true);
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
						executeSentence(properties.get(s), systemObject, null);
					}
				}
			}
		}
}

	public boolean validateUserPassword(String accountName, Password password)
			throws RemoteException, InternalErrorException {
		Account acc = new Account();
		acc.setName(accountName);
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
					if ( executeSentence(properties.get(s), systemObject, null) > 0 )
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
	