package com.soffid.iam.sync.agent;

import java.rmi.RemoteException;

import com.soffid.iam.api.CustomObject;
import com.soffid.iam.sync.intf.CustomObjectMgr;

import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.ng.sync.intf.ExtensibleObject;
import es.caib.seycon.ng.sync.intf.ExtensibleObjectMapping;
import es.caib.seycon.ng.sync.intf.ExtensibleObjects;

public class SQLAgent2 extends SQLAgent implements CustomObjectMgr {

	public SQLAgent2() throws RemoteException {
		super();
	}

	@Override
	public ExtensibleObject getNativeObject(es.caib.seycon.ng.comu.SoffidObjectType type, String object1, String object2)
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
	public ExtensibleObject getSoffidObject(es.caib.seycon.ng.comu.SoffidObjectType type, String object1, String object2)
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
		ExtensibleObject soffidObject = new es.caib.seycon.ng.sync.engine.extobj.CustomExtensibleObject(obj, getServer());
		for ( ExtensibleObjectMapping objectMapping: objectMappings)
		{
			if (objectMapping.appliesToSoffidObject(soffidObject))
			{
				ExtensibleObject systemObject = objectTranslator.generateObject(soffidObject, objectMapping);
				updateObject(soffidObject, systemObject);
			}
		}
	}

	public void removeCustomObject(CustomObject obj) throws RemoteException, InternalErrorException {
		ExtensibleObject soffidObject = new es.caib.seycon.ng.sync.engine.extobj.CustomExtensibleObject(obj, getServer());
		for ( ExtensibleObjectMapping objectMapping: objectMappings)
		{
			if (objectMapping.appliesToSoffidObject(soffidObject))
			{
				ExtensibleObject systemObject = objectTranslator.generateObject(soffidObject, objectMapping);
				delete(null, systemObject, objectMapping.getProperties(), objectMapping.getSystemObject());
			}
		}
	}
}
