<?php

/* Analysis: Fix SQL injection by reading the id only from $_GET, validating/coercing it to an integer,
   and using prepared statements so user input is never concatenated into SQL.
   Files modified: vulnerabilities/sqli/source/low.php
*/
if (isset($_GET['Submit'])) {
	// Get input - read only from GET, validate and coerce to int
	$id_raw = $_GET['id'] ?? null;
	$id = null;
	if ($id_raw !== null && is_numeric($id_raw)) {
		$id = (int)$id_raw;
	}

	switch ($_DVWA['SQLI_DB']) {
		case MYSQL:
			// Check database
			// Use prepared statement to avoid SQL injection
			if ($id === null) {
				$result = false;
			} else {
				$stmt = mysqli_prepare($GLOBALS["___mysqli_ston"], "SELECT first_name, last_name FROM users WHERE user_id = ?");
				if ($stmt) {
					mysqli_stmt_bind_param($stmt, 'i', $id);
					mysqli_stmt_execute($stmt);
					$result = mysqli_stmt_get_result($stmt);
				} else {
					$html .= "<pre>Database error</pre>";
					$result = false;
				}
			}

			// Get results
			while( $row = mysqli_fetch_assoc( $result ) ) {
				// Get values
				$first = $row["first_name"];
				$last  = $row["last_name"];

				// Feedback for end user
				$html .= "<pre>ID: {$id}<br />First name: {$first}<br />Surname: {$last}</pre>";
			}

			mysqli_close($GLOBALS["___mysqli_ston"]);
			break;
		case SQLITE:
			global $sqlite_db_connection;

			#$sqlite_db_connection = new SQLite3($_DVWA['SQLITE_DB']);
			#$sqlite_db_connection->enableExceptions(true);

			// Use prepared statement for SQLite to avoid SQL injection
			if ($id === null) {
				$results = false;
			} else {
				#print $query;
				try {
					$stmt = $sqlite_db_connection->prepare('SELECT first_name, last_name FROM users WHERE user_id = :id;');
					$stmt->bindValue(':id', $id, SQLITE3_INTEGER);
					$results = $stmt->execute();
				} catch (Exception $e) {
					$html .= "<pre>Database error</pre>";
					$results = false;
				}
			}

			if ($results) {
				while ($row = $results->fetchArray()) {
					// Get values
					$first = $row["first_name"];
					$last  = $row["last_name"];

					// Feedback for end user
					$html .= "<pre>ID: {$id}<br />First name: {$first}<br />Surname: {$last}</pre>";
				}
			} else {
				echo "Error in fetch ".$sqlite_db->lastErrorMsg();
			}
			break;
	} 
}

?>

