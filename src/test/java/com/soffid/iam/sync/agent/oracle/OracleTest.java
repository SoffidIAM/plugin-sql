package com.soffid.iam.sync.agent.oracle;

import java.sql.CallableStatement;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;

import oracle.jdbc.driver.OracleTypes;

public class OracleTest {

	public static void main(String args[]) throws ClassNotFoundException, InstantiationException, IllegalAccessException, SQLException {
		String driverClass = "oracle.jdbc.driver.OracleDriver";
		Class c = Class.forName(driverClass);
		DriverManager.registerDriver((java.sql.Driver) c.newInstance());

		Connection conn = DriverManager.getConnection(
				"jdbc:oracle:thin:@dbtest21.local.modernprocessing.lu:1521:bwtest4", 
				"bw_ascard",
				"uKdpT0XW");

		// List all user ids
		CallableStatement ps = conn.prepareCall("{call \n"
				+ "DECLARE \n"
				+ "C SYS_REFCURSOR; \n"
				+ "D SYS_REFCURSOR ; \n"
				+ "BEGIN  \n"
				+ "BW_SOFFID_INTEGRATION.GET_ALL_USERS(D);\n "
				+ "OPEN C FOR SELECT 10 FROM DUAL; \n"
				+ "OPEN C FOR SELECT 1 \"a\" FROM DUAL WHERE 1<0;"
				+ "? := D;\n"
				+ "END} \n");
		ps.registerOutParameter(1, OracleTypes.CURSOR);
		ps.execute();
		
		ResultSet rs = (ResultSet) ps.getObject(1);
//		ResultSet rs = ps.getResultSet();
		while (rs.next())
		{
			System.out.println(rs.getString(1));
			System.out.println ("===");
		}
		rs.close ();
		ps.close ();
		// Get data for userid
		ps = conn.prepareCall("{call \n"
				+ "BW_SOFFID_INTEGRATION.GET_USER(?, ?)\n "
				+ "} \n");
		ps.setString(1,  "999999");
		ps.registerOutParameter(2, OracleTypes.CURSOR);
		ps.execute();
		
		rs = (ResultSet) ps.getObject(2);
		while (rs.next())
		{
			System.out.println(rs.getString(1));
			System.out.println(rs.getString(2));
			System.out.println(rs.getString(3));
			System.out.println ("===");
		}
		
		ps = conn.prepareCall("{call \n"
			+"DECLARE  \n"
			+"  C SYS_REFCURSOR ; n"
			+"BEGIN \n"
			+"   BW_SOFFID_INTEGRATION.GET_ALL_INSTITUTIONS(C);\n"
//			+"   FOR ROW IN C LOOP; \n"
//			+"      IF (ROW.INSTITUTION_NUMBER = '00000003') THEN \n"
//			+"         BREAK; \n"
//			+"      END IF; \n"
//			+"   END LOOP; \n"
//			+"   ? := C \n"
			+ "? := C\n"
			+"END}");
		
		String s = ("{call \n"
				+ "DECLARE \n"
				+ "n1 VARCHAR2(8);"
				+ "INSTITUTION_NUMBER VARCHAR2(8);"
				+ "n3 VARCHAR2(16);"
				+ "n4 VARCHAR2(3);"
				+ "n5 VARCHAR2(8);"
				+ "n6 RAW(8);"
				+ "n7 VARCHAR2(4);"
				+ "INSTITUTION_NAME VARCHAR2(32);"
				+ "n8 VARCHAR2(3);"
				+ "n9 VARCHAR2(40);"
				+ "n10 VARCHAR2(50);"
				+ "n11 VARCHAR2(50);"
				+ "n12 CHAR(1);"
				+ "n13 CHAR(4);"
				+ "n14 VARCHAR2(20);"
				+ "n15 VARCHAR2(15);"
				+ "n16 VARCHAR2(15);"
				+ "n17 VARCHAR2(35);"
				+ "n18 VARCHAR2(35);"
				+ "n19 VARCHAR2(35);"
				+ "n20 VARCHAR2(35);"
				+ "n21 VARCHAR2(1);"
				+ "n22 VARCHAR2(10);"
				+ "n23 VARCHAR2(128);"
				+ "C SYS_REFCURSOR; \n"
				+ "BEGIN  \n"
				+ "BW_SOFFID_INTEGRATION.GET_ALL_INSTITUTIONS(C);\n "
				+ "LOOP FETCH C INTO n1, institution_number,"
				+ "	n3, n4, n5,n6,n7, INSTITUTION_NAME, n8,"
				+ "n9,n10,n11,n12,n13,n14,n15,n16,n17,n18,n19,"
				+ "n20,n21,n22,n23; \n"
				+ "EXIT WHEN C%NOTFOUND;"
				+ "IF INSTITUTION_NUMBER='00000003' THEN \n"
				+ "OPEN C FOR SELECT INSTITUTION_NUMBER \"INSTITUTION_NUMBER\", INSTITUTION_NAME \"INSTITUTION_NAME\" FROM DUAL;\n"
				+ "EXIT;\n"
				+ "END IF;\n"
				+ "END LOOP;  \n"
				+ "? := C;\n"
				+ "END} \n");
		System.out.println(s);
		ps = conn.prepareCall(s);
		//		ps.setString(1,  "00000003");
		
		ps.registerOutParameter(1, OracleTypes.CURSOR);
		ps.execute();
		rs = (ResultSet) ps.getObject(1);
		System.out.println ("INSTITUTIONS");
		while (rs.next())
		{
			System.out.println(rs.getString(1));
			System.out.println(rs.getString(2));
			System.out.println(rs.getString("INSTITUTION_NUMBER"));
			System.out.println(rs.getString("INSTITUTION_NAME"));
			System.out.println ("===");
		}

		// Get data for userid
		ps = conn.prepareCall("{call \n"
				+ "BW_SOFFID_INTEGRATION.GET_ALL_MASK_MODES(?)\n "
				+ "} \n");

		ps.registerOutParameter(1, OracleTypes.CURSOR);
		ps.execute();
		rs = (ResultSet) ps.getObject(1);

		while (rs.next())
		{
			System.out.println(rs.getString(1));
			System.out.println(rs.getString(2));
			System.out.println ("===");
		}
		

	}
}
