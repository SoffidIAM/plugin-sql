package com.soffid.iam.sync.agent;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.lang.reflect.Method;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

import org.apache.commons.io.output.ByteArrayOutputStream;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.json.JSONTokener;
import org.slf4j.Logger;

import com.soffid.iam.api.Account;
import com.soffid.iam.api.RoleGrant;
import com.soffid.iam.remote.RemoteServiceLocator;
import com.soffid.iam.sync.intf.ExtensibleObject;
import com.soffid.iam.sync.service.ServerService;

import es.caib.seycon.ng.exception.AccountAlreadyExistsException;
import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.util.Base64;

public class DeltaChangesManager {
	private static final String ATTRIBUTES = "a";
	private static final String GRANTS = "g";
	private static final String DOMAIN_VALUE = "d";
	private static final String ROLE_NAME = "n";
	public static final String STATUS_ATTRIBUTE = "$soffid$previous-status";
	static java.text.SimpleDateFormat dateFormat = new SimpleDateFormat("dd-MM-yyyy HH:mm:ss");
	private Logger log;
	
	public DeltaChangesManager(Logger log2) {
		log = log2;
	}

	public void apply(Account acc, List<RoleGrant> currentGrants, List<RoleGrant> newGrants, ServerService svc, boolean delta, RoleGrantDeltaChangesAction action) 
			throws Exception {
		if (delta) {
			List<RoleGrant> previousGrants = getPreviousGrants(acc);
			for (RoleGrant newGrant: newGrants) {
				RoleGrant cg = find(newGrant, previousGrants) ;
				if ( cg != null) { // Already asigned in the past => ignore
					previousGrants.remove(cg);
					if (find(newGrant, currentGrants) == null)
						log.warn("Permission "+newGrant.getRoleName()+" has been removed locally");
				}
				else if (find(newGrant, currentGrants) == null) {
					action.add(newGrant);
				}
			}
			for (RoleGrant oldGrant: previousGrants) {
				RoleGrant cg = find(oldGrant, currentGrants) ;
				if ( cg != null) { // Grant must be removed
					action.remove(cg);
				}
			}
			for (RoleGrant grant: currentGrants) {
				if (find(grant, newGrants) == null) {
					log.warn("Permission "+grant.getRoleName()+" has been added locally");
				}
			}
			saveGrants(acc, newGrants, svc);
		} else {
			currentGrants = new LinkedList<>(currentGrants);
			for (RoleGrant newGrant: newGrants) {
				RoleGrant cg = find(newGrant, currentGrants) ;
				if ( cg != null) { // Already removed in the past => ignore
					currentGrants.remove(cg);
				} else {
					action.add(newGrant);
				}
			}
			for (RoleGrant oldGrant: currentGrants) {
				action.remove(oldGrant);
			}
		}
	}

	private RoleGrant find(RoleGrant newGrant, List<RoleGrant> currentGrants) {
		for (RoleGrant g: currentGrants) {
			if (g.getRoleName().equals(newGrant.getRoleName())) {
				if (g.getDomainValue() == null ? 
						newGrant.getDomainValue() == null : 
						g.getDomainValue().equals(newGrant.getDomainValue()))
					return g;
			}
		}
		return null;
	}

	private List<RoleGrant> getPreviousGrants(Account acc) throws JSONException, IOException {
		LinkedList<RoleGrant> r = new LinkedList<RoleGrant>();
		byte[] prev = (byte[]) acc.getAttributes().get(STATUS_ATTRIBUTE);
		if (prev != null) {
			try {
				ByteArrayInputStream in = new ByteArrayInputStream(prev);
				GZIPInputStream gzip = new GZIPInputStream(in);
	
				JSONObject o = new JSONObject(new JSONTokener(new InputStreamReader(gzip,"UTF-8")));
				gzip.close();
				
				JSONArray a = o.optJSONArray(GRANTS);
				if (a != null) {
					for (int i = 0; i < a.length(); i++) {
						JSONObject rg = a.getJSONObject(i);
						RoleGrant grant = new RoleGrant();
						grant.setOwnerAccountName(acc.getName());
						grant.setOwnerSystem(acc.getSystem());
						grant.setSystem(acc.getSystem());
						grant.setRoleName(rg.getString(ROLE_NAME));
						if (rg.has(DOMAIN_VALUE))
							grant.setDomainValue(rg.optString(DOMAIN_VALUE));
						r.add(grant);
					}
				}
			} catch (IOException e) {
				return r;
			}
			
		}
		
		return r;
	}
	
	public void saveGrants(Account acc, List<RoleGrant> grants, ServerService svc) throws JSONException, InternalErrorException, AccountAlreadyExistsException, IOException {
		if (updateDeltaAttribute(acc, grants)) {
			try {
				Method m = svc.getClass().getMethod("reconcileAccount", Account.class, List.class);
				svc.reconcileAccount(acc, null);
			} catch (NoSuchMethodException e) {
				new RemoteServiceLocator().getAccountService().updateAccount2(acc);
			}
		}
	}
	
	public boolean updateDeltaAttribute(Account acc, List<RoleGrant> grants) throws IOException {
		JSONObject o = null;
		try {
			if (acc != null && acc.getAttributes() != null) {
				byte[] prev = (byte[]) acc.getAttributes().get(STATUS_ATTRIBUTE);
				if (prev != null) {
					ByteArrayInputStream in = new ByteArrayInputStream(prev);
					GZIPInputStream gzip = new GZIPInputStream(in);
					o = new JSONObject(new JSONTokener(new InputStreamReader(gzip,"UTF-8")));
				}
			}
		} catch (IOException e) {}
		if (o == null) 
			o = new JSONObject();
		String src = o.toString();
		JSONArray a = new JSONArray();
		grants = new LinkedList<RoleGrant>(grants);
		Collections.sort(grants, new Comparator<RoleGrant>() {
			public int compare(RoleGrant o1, RoleGrant o2) {
				int r = o1.getRoleName().compareTo(o2.getRoleName());
				if (r == 0) {
					if (o1.getDomainValue() == null && o2.getDomainValue() == null)
						r = 0;
					else if (o1.getDomainValue() == null && o2.getDomainValue() != null)
						r = -1;
					else if (o1.getDomainValue() != null && o2.getDomainValue() == null)
						r = 1;
					else
						r = o1.getDomainValue().compareTo(o2.getDomainValue());
				}
				return r;
			}
		});
		for (RoleGrant grant: grants) {
			JSONObject rg = new JSONObject();
			rg.put(ROLE_NAME, grant.getRoleName());
			rg.put(DOMAIN_VALUE, grant.getDomainValue());
			a.put(rg);
		}
		o.put(GRANTS, a);
		
		if (!src.equals(o.toString())) {
			ByteArrayOutputStream out = new ByteArrayOutputStream();
			GZIPOutputStream gzip = new GZIPOutputStream(out);
			gzip.write(o.toString().getBytes("UTF-8"));
			gzip.close();
			byte[] next = out.toByteArray();
			if (acc.getAttributes() == null)
				acc.setAttributes(new HashMap<>());
			acc.getAttributes().put(STATUS_ATTRIBUTE, next);
			return true;
		}
		else
			return false;
	}
	
	public boolean updateDeltaAttribute(Account acc, ExtensibleObject target) throws InternalErrorException {
		log.info("Updating delta attributes");
		JSONObject o = null;
		if (acc == null || acc.getId() == null)
			return false;
		try {
			byte[] prev = (byte[]) acc.getAttributes().get(STATUS_ATTRIBUTE);
			if (prev != null) {
				ByteArrayInputStream in = new ByteArrayInputStream(prev);
				GZIPInputStream gzip = new GZIPInputStream(in);
				o = new JSONObject(new JSONTokener(new InputStreamReader(gzip,"UTF-8")));
			}
		} catch (IOException e) {}
		if (o == null) 
			o = new JSONObject();
		log.info("Result = "+o.toString());
		String src = o.toString();
		JSONObject attributes = new JSONObject();
		LinkedList<String> keys = new LinkedList<String>(target.keySet());
		Collections.sort(keys);
		for (String key: keys) {
			Object value = target.get(key);
			attributes.put(key, flatten(value));
		}
		o.put(ATTRIBUTES, attributes);
		log.info("Result = "+o.toString());
		
		if (!src.equals(o.toString())) {
			try {
				log.info("Dumping");
				ByteArrayOutputStream out = new ByteArrayOutputStream();
				GZIPOutputStream gzip = new GZIPOutputStream(out);
				gzip.write(o.toString().getBytes("UTF-8"));
				gzip.close();
				byte[] next = out.toByteArray();
				acc.getAttributes().put(STATUS_ATTRIBUTE, next);
				log.info("Dumped");
				return true;
			} catch (IOException e) {
				throw new InternalErrorException("Error saving account attributes", e);
			}
		}
		else
			return false;
	}

	private String flatten(Object value) {
		if (value == null)
			return null;
		else if (value instanceof Date)
			return dateFormat.format((Date)value);
		else if (value instanceof Calendar)
			return dateFormat.format(((Calendar)value).getTime());
		else if (value instanceof byte[])
			return Base64.encodeBytes((byte[])value, Base64.DONT_BREAK_LINES);
		else
			return value.toString();
	}

	private ExtensibleObject getPreviousObject(Account acc) throws JSONException, IOException {
		ExtensibleObject r = new ExtensibleObject();
		byte[] prev = (byte[]) acc.getAttributes().get(STATUS_ATTRIBUTE);
		if (prev != null) {
			try {
				ByteArrayInputStream in = new ByteArrayInputStream(prev);
				GZIPInputStream gzip = new GZIPInputStream(in);
	
				JSONObject o = new JSONObject(new JSONTokener(new InputStreamReader(gzip,"UTF-8")));
				JSONObject attributes = o.optJSONObject(ATTRIBUTES);
				if (attributes != null) {
					for (Iterator it = attributes.keys(); it.hasNext();) {
						String key = (String) it.next();
						r.put(key, attributes.get((String) key));
					}
				}
			} catch (IOException e) {
				return r;
			}
			
		}
		
		return r;
	}
	
	public ExtensibleObject merge(Account acc, ExtensibleObject currentObject, ExtensibleObject newObject, ServerService svc, boolean delta) throws InternalErrorException {
		if (delta)
		{
			try {
				ExtensibleObject previous = getPreviousObject(acc);
				ExtensibleObject newObject2 = new ExtensibleObject();
				newObject2.setObjectType(newObject.getObjectType());
				for (String key: newObject.keySet()) {
					final Object value = newObject.get(key);
					String flatValue = flatten(value);
					String previousValue = (String) previous.get(key);
					boolean changed = flatValue == null?  previous != null: !flatValue.equals(previousValue);
					if (!changed && currentObject.containsKey(key)) {
						Object oldValue = currentObject.get(key);
						if (oldValue == null ? value != null: !oldValue.equals(value))
							log.warn("Attribute "+key+" has been modified locally. Keeping current value");
						newObject2.put(key, oldValue);
					} else {
						newObject2.put(key, value);
					}
				}
				return newObject2;
			} catch (JSONException e) {
				throw new InternalErrorException("Error merging account attributes", e);
			} catch (IOException e) {
				throw new InternalErrorException("Error merging account attributes", e);
			}
		}
		else
			return newObject;
	}

}
