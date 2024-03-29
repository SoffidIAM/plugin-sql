package com.soffid.iam.sync.agent;

import java.rmi.RemoteException;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.Collection;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import com.soffid.iam.api.CustomObject;
import com.soffid.iam.sync.intf.CustomObjectMgr;

import com.soffid.iam.api.Group;
import com.soffid.iam.api.SoffidObjectType;
import com.soffid.iam.api.User;
import es.caib.seycon.ng.exception.InternalErrorException;
import com.soffid.iam.sync.engine.extobj.ValueObjectMapper;
import com.soffid.iam.sync.intf.AuthoritativeChange;
import com.soffid.iam.sync.intf.AuthoritativeChangeIdentifier;
import com.soffid.iam.sync.intf.ExtensibleObject;
import com.soffid.iam.sync.intf.ExtensibleObjectMapping;

public class SQLAgent2 extends SQLAgent implements CustomObjectMgr {

	public SQLAgent2() throws RemoteException {
		super();
	}

	@Override
	public ExtensibleObject getNativeObject(com.soffid.iam.api.SoffidObjectType type, String object1, String object2)
			throws RemoteException, InternalErrorException {
		try {
			ExtensibleObject sourceObject = getExtensibleObject(type, object1, object2);
			for (ExtensibleObjectMapping map : objectMappings) {
				if (map.appliesToSoffidObject(sourceObject))
				{
					ExtensibleObject translatedSample = objectTranslator.generateObject(sourceObject, map);
					for (String tag: map.getProperties().keySet()) 
					{
						if (tag.startsWith("select") && ! tag.startsWith("selectAll"))
						{
							for ( ExtensibleObject obj : selectSystemObjects (translatedSample, map, 
								map.getProperties().get(tag),
								 map.getProperties().get(tag+"Filter")) )
							{
								debugObject("Got system object", obj, "");
								for (String key: obj.keySet())
								{
									Object o = obj.get(key);
									if (o != null && o.getClass().getName().endsWith("NullSqlObjet"))
										obj.put(key, null);
								}
								return obj;
							}
						}
					}
				}
			}
			return null;
		} catch (Exception e) {
			throw new InternalErrorException("Error searching for LDAP object", e);
		}
	}

	@Override
	public ExtensibleObject getSoffidObject(com.soffid.iam.api.SoffidObjectType type, String object1, String object2)
			throws RemoteException, InternalErrorException {
		try {
			ExtensibleObject sourceObject = getExtensibleObject(type, object1, object2);
			for (ExtensibleObjectMapping map : objectMappings) {
				if (map.appliesToSoffidObject(sourceObject))
				{
					ExtensibleObject translatedSample = objectTranslator.generateObject(sourceObject, map);
					for (String tag: map.getProperties().keySet()) 
					{
						if (tag.startsWith("select") && ! tag.startsWith("selectAll"))
						{
							for ( ExtensibleObject obj : selectSystemObjects (translatedSample, map, 
								map.getProperties().get(tag),
								 map.getProperties().get(tag+"Filter")) )
							{
								debugObject("Got system object", obj, "");
								ExtensibleObject soffidObj = objectTranslator.parseInputObject(obj, map);
								debugObject("Translated soffid object", soffidObj, "");
							
								for (String key: obj.keySet())
								{
									Object o = obj.get(key);
									if (o != null && o.getClass().getName().endsWith("NullSqlObjet"))
										obj.put(key, null);
								}

								return soffidObj;
							}
						}
					}
				}
			}
			return null;
		} catch (Exception e) {
			throw new InternalErrorException("Error searching for LDAP object", e);
		}
	}

	public void updateCustomObject(CustomObject obj) throws RemoteException, InternalErrorException {
		ExtensibleObject soffidObject = new com.soffid.iam.sync.engine.extobj.CustomExtensibleObject(obj, getServer());
		for ( ExtensibleObjectMapping objectMapping: objectMappings)
		{
			if (objectMapping.appliesToSoffidObject(soffidObject))
			{
				ExtensibleObject systemObject = objectTranslator.generateObject(soffidObject, objectMapping);
				updateObject(null, soffidObject, systemObject);
			}
		}
	}

	public void removeCustomObject(CustomObject obj) throws RemoteException, InternalErrorException {
		ExtensibleObject soffidObject = new com.soffid.iam.sync.engine.extobj.CustomExtensibleObject(obj, getServer());
		for ( ExtensibleObjectMapping objectMapping: objectMappings)
		{
			if (objectMapping.appliesToSoffidObject(soffidObject))
			{
				ExtensibleObject systemObject = objectTranslator.generateObject(soffidObject, objectMapping);
				delete(null, systemObject, objectMapping.getProperties(), objectMapping.getSystemObject());
			}
		}
	}

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
				log.info("Object type: "+objMapping.getSystemObject());
				if (objMapping.getSoffidObject().equals(SoffidObjectType.OBJECT_USER) ||
						objMapping.getSoffidObject().equals(SoffidObjectType.OBJECT_GROUP) ||
						objMapping.getSoffidObject().equals(SoffidObjectType.OBJECT_CUSTOM) ||
						objMapping.getSoffidObject().equals(SoffidObjectType.OBJECT_AUTHORITATIVE_CHANGE))
				{
					log.info("Ignored");
					for (String tag: getTags (objMapping.getProperties(), "selectAll", objMapping.getSystemObject()))
					{
						String filter = objMapping.getProperties().get(tag+"Filter");
						String sentence = objMapping.getProperties().get(tag);
						log.info("Getting data");
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
											} else {
												Group gr =  new ValueObjectMapper().parseGroup(translated);
												Long changeId = new Long(lastChangeId++);
												ch = new AuthoritativeChange();
												ch.setId(new AuthoritativeChangeIdentifier());
												ch.getId().setInternalId(changeId);
												ch.setGroup(gr);
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

	public Collection<AuthoritativeChange> getChanges(String lastChange)
			throws InternalErrorException {
		
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
				log.info("Object type: "+objMapping.getSystemObject());
				if (objMapping.getSoffidObject().equals(SoffidObjectType.OBJECT_USER) ||
						objMapping.getSoffidObject().equals(SoffidObjectType.OBJECT_GROUP) ||
						objMapping.getSoffidObject().equals(SoffidObjectType.OBJECT_CUSTOM) ||
						objMapping.getSoffidObject().equals(SoffidObjectType.OBJECT_AUTHORITATIVE_CHANGE))
				{
					log.info("Ignored");
					for (String tag: getTags (objMapping.getProperties(), "selectAll", objMapping.getSystemObject()))
					{
						String filter = objMapping.getProperties().get(tag+"Filter");
						String sentence = objMapping.getProperties().get(tag);
						log.info("Getting data");
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
											} else {
												Group gr =  new ValueObjectMapper().parseGroup(translated);
												Long changeId = new Long(lastChangeId++);
												ch = new AuthoritativeChange();
												ch.setId(new AuthoritativeChangeIdentifier());
												ch.getId().setInternalId(changeId);
												ch.setGroup(gr);
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
}
