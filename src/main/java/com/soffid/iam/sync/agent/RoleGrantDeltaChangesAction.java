package com.soffid.iam.sync.agent;

import com.soffid.iam.api.RoleGrant;

public interface RoleGrantDeltaChangesAction {
	void add(RoleGrant rg) throws Exception;
	void remove(RoleGrant rg) throws Exception;
}
