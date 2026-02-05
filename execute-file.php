<?php

define( 'DVWA_WEB_PAGE_TO_ROOT', '' );
require_once DVWA_WEB_PAGE_TO_ROOT . 'dvwa/includes/dvwaPage.inc.php';

dvwaPageStartup( array( 'authenticated' ) );
dvwaDatabaseConnect();

$page = dvwaPageNewGrab();
$page[ 'title' ]   = 'Workflow Runner' . $page[ 'title_separator' ] . $page[ 'title' ];
$page[ 'page_id' ] = 'workflow';

if( isset( $_POST[ 'action' ] ) && $_POST[ 'action' ] === 'refresh_status' ) {
	dvwaMessagePush( 'Status refreshed.' );
}

$messagesHtml  = messagesPopAllToHtml();
$currentUser   = dvwaCurrentUser();
$securityLevel = dvwaSecurityLevelGet();
$theme         = dvwaThemeGet();

$page[ 'body' ] .= "
<div class=\"body_padded\">
	<h1>Workflow Runner</h1>
	<p>This page is part of the main application flow and uses existing services.</p>
	<ul>
		<li>Current user: {$currentUser}</li>
		<li>Security level: {$securityLevel}</li>
		<li>Theme: {$theme}</li>
	</ul>

	<form action=\"execute-file.php\" method=\"post\">
		<input type=\"hidden\" name=\"action\" value=\"refresh_status\" />
		<input type=\"submit\" value=\"Refresh Status\" />
	</form>

	{$messagesHtml}

	<h2>Quick Links</h2>
	<ul>
		<li><a href=\"" . DVWA_WEB_PAGE_TO_ROOT . "security.php\">Security Settings</a></li>
		<li><a href=\"" . DVWA_WEB_PAGE_TO_ROOT . "setup.php\">Setup / Reset DB</a></li>
		<li><a href=\"" . DVWA_WEB_PAGE_TO_ROOT . "instructions.php\">Instructions</a></li>
	</ul>
</div>\n";

dvwaHtmlEcho( $page );

?>
