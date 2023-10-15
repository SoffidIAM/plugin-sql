package com.soffid.iam.sync.agent;

import java.sql.Connection;
import java.sql.Driver;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Properties;

import com.soffid.iam.sync.engine.pool.JDBCPool;

public class SQLJDBCPool extends JDBCPool 
{
	String startupSql;
	
	@Override
	protected Connection createConnection() throws SQLException {
		Connection c;
		Driver driver = null;
		try {
			if (getUrl().startsWith("jdbc:mysql:")) {
				driver = (Driver) Class.forName("com.mysql.jdbc.Driver").newInstance();
			}
			if (getUrl().startsWith("jdbc:mariadb:")) {
				driver = (Driver) Class.forName("org.mariadb.jdbc.Driver").newInstance();
			}
		} catch (Exception e) {
		}

		if (driver == null) {
			c = super.createConnection();
		}
		else 
		{
			Properties p = new Properties ();
			p.setProperty("user", getUser());
			p.setProperty("password", getPassword());
			c = driver.connect(getUrl(), p);
		}

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
