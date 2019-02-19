package com.soffid.iam.sync.agent;

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;

import com.soffid.iam.sync.engine.pool.JDBCPool;

public class SQLJDBCPool extends JDBCPool 
{
	String startupSql;
	
	@Override
	protected Connection createConnection() throws SQLException {
		Connection c = super.createConnection();
		if (startupSql != null && !startupSql.trim().isEmpty())
		{
			Statement stmt = c.createStatement();
			stmt.executeQuery(startupSql);
			stmt.close();
		}
		return c;
	}

	public String getStartupSql() {
		return startupSql;
	}

	public void setStartupSql(String startupSql) {
		this.startupSql = startupSql;
	}

}
