<?php
/*
Plugin Name: ULeak Security Plugin
Description: A Wordpress security plugin by Crossvault GmbH. Our Wordpress Cleanup Plugin will help you to detect all possible malware on PHP and MySQL.
Author: zephyrus1337
Version: 1.0
*/
@ini_set( 'max_execution_time', 180 );

/**
 * Set up the menu item and register with hooks to print JS and help.
 */
function uleak_menu() {
	$page_hook = add_management_page( 'ULeak Security', 'ULeak Security', 'manage_options', 'uleak', 'uleak_admin_page' );
	if ( $page_hook ) {
		add_action( "admin_print_styles-$page_hook", 'add_thickbox' );
		add_action( "admin_footer-$page_hook", 'uleak_admin_scripts' );
		add_action( "load-$page_hook", 'uleak_help_tabs' );
	}
}
add_action( 'admin_menu', 'uleak_menu' );

function uleak_help_tabs() {
	$screen = get_current_screen();
	$screen->add_help_tab( array(
		'id' => 'interpreting-results',
		'title' => 'Different Result Levels',
		'content' => '<p><strong>Understanding the three different result levels</strong></p>
		<ul>
			<li><strong>Severe:</strong> results that are often strong indicators of a hack (though they are not definitive proof). This critical results will synchronized to your ULeak dashboard and you get email alert notifications.</li>
			<li><strong>Warning:</strong> these results are more commonly found in innocent circumstances than Severe matches, but they should still be treated with caution</li>
			<li><strong>Note:</strong> lowest priority, showing results that are very commonly used in legitimate code or notifications about events such as skipped files</li>
		</ul><p>Severe scan results will automated synchronized to your dashboard at www.uleak.de</p>',
	) );
	$screen->add_help_tab( array(
		'id' => 'advice-for-the-owned',
		'title' => 'ULeak Support',
		'content' => '<p><strong>Contact ULeak Support</strong></p>
<ul>
    <li><a href="http://uleak.de/support">ULeak: Support Contact</a></li>
    <li><a href="http://uleak.de/login">ULeak: Login</a></li>
    <li><a href="http://uleak.de/pricing">ULeak: Sign up</a></li>
</ul>',
	) );
}

/**
 * Print scripts that power paged scanning and diff modal.
 */
function uleak_admin_scripts() { ?>
	<script type="text/javascript">
		jQuery(document).ready(function($) {
			$('#run-scanner').click( function() {
				var fsl = $('#filesize_limit').val(),
					max = parseInt( $('#max_test_files').val(), 10 );

				$.ajaxSetup({
					type: 'POST',
					url: ajaxurl,
					complete: function(xhr,status) {
						if ( status != 'success' ) {
							$('#scan-loader img').hide();
							$('#scan-loader span').html( 'An error occurred. Please try again later.' );
						}
					}
				});

				$('#scan-results').hide();
				$('#scan-loader').show();
				uleak_file_scan(0, fsl, max);
				return false;
			});

			$('#hide-skipped').toggle( function() {
				$('.skipped-file').hide();
				$(this).html('Show skipped files');
			}, function() {
				$('.skipped-file').show();
				$(this).html('Hide skipped files');
			});

			$('.view-diff').click( function() {
				// escaped ampersands returned by wp_nonce_url don't play nicely here
				var nonce = '_ajax_nonce=<?php echo wp_create_nonce( 'uleak_view_diff' ); ?>';
				tb_show( 'File changes', ajaxurl + '?action=uleak_view_diff&' + nonce + '&file=' + this.id, false );
				return false;
			});
		});

		var uleak_nonce = '<?php echo wp_create_nonce( 'uleak_scan' ); ?>',
			uleak_file_scan = function(s, fsl, max) {
				jQuery.ajax({
					data: {
						action: 'uleak_file_scan',
						start: s,
						filesize_limit: fsl,
						max_batch_size: max,
						_ajax_nonce: uleak_nonce
					}, success: function(r) {
						var res = jQuery.parseJSON(r);
						if ( 'running' == res.status ) {
							jQuery('#scan-loader span').html(res.data);
							uleak_file_scan(s+max, fsl, max);
						} else if ( 'error' == res.status ) {
							// console.log( r );
							jQuery('#scan-loader img').hide();
							jQuery('#scan-loader span').html(
								'An error occurred: <pre style="overflow:auto">' + r.toString() + '</pre>'
							);
						} else {
							uleak_db_scan();
						}
					}
				});
			}, uleak_db_scan = function() {
				jQuery('#scan-loader span').html('Scanning database...');
				jQuery.ajax({
					data: {
						action: 'uleak_db_scan',
						_ajax_nonce: uleak_nonce
					}, success: function(r) {
						jQuery('#scan-loader img').hide();
						jQuery('#scan-loader span').html('Scan complete. Refresh the page to view the results.');
						window.location.reload(false);
					}
				});
			};
	</script>
	<?php
}

/**
 * add_management_page callback
 */
function uleak_admin_page() {
	global $wpdb;
	// non-ajax scan form processing
	if ( isset($_POST['action']) && 'scan' == $_POST['action'] ) {
		check_admin_referer( 'uleak-scan_all' );

		$fsl = ( ! isset($_POST['filesize_limit']) || ! is_numeric($_POST['filesize_limit']) ) ? 400 : (int) $_POST['filesize_limit'];

		$scanner = new File_Uleak_Scanner( ABSPATH, array( 'start' => 0, 'fsl' => $fsl ) );
		$scanner->run();
		$scanner = new DB_Uleak_Scanner();
		$scanner->run();
	}
	echo '<div class="wrap">';
	echo '<a href="http://uleak.de" target="_blank"><img src="'.plugins_url( 'img/logo.png', __FILE__ ).'" alt="ULeak Logo" /></a>';
	$user_credentials = $wpdb->get_results( 'SELECT * FROM '.$wpdb->prefix ."uleak_customer".' WHERE id = 1');
	foreach($user_credentials as $key => $row) {
		$user['username'] = $row->username;
		$user['pwd'] = base64_decode($row->pwd);
		$user['email'] = $row->email;
		$user['apikey'] = $row->apikey;
	}
	if(!empty($user['pwd'])){
		$login['username'] = $user['username'];
		$login['passwort'] = $user['pwd'];
		$login['apikey'] = $user['apikey'];
		$data = curl_helper_post($login, false, 'authenticate_api_user');
		if($data->status == 'OK'){
			$wpdb->update(
				$wpdb->prefix."uleak_customer",
				array('portfolio_id' => $data->portfolio_id),
				array('id' => 1),
				array('%d'),
				array('%d')
			);
		}
	}
	echo '<h3>Security and Password Validation Plugin</h3><p>This plguin provides a malware scan to find all backdoor scripts and potential risks on your Wordpress installation. Log in to your ULeak API account and synchronize daily scanning results to your Uleak dashboard. You can find the daily synchronisation process in the Wordpress cron event schedular. We will send you also an email alert if a scanner finds an infected file. For support and system cleanups you also can contact our <a href="http://uleak.de/support" target="_blank">support</a> team. If you dont have a ULeak account see our pricing and sign up <a href="http://uleak.de/pricing">here</a>.</p>';
	echo '<h3>WordPress Source Hashes</h3>';
	if(isset($_GET['msg'])){
		if($_GET['msg'] == 2){
			echo '<p style="color:green;">Successfully updated source hashes of your current WordPress version.</p>';
		}elseif($_GET['msg'] == 3){
			echo '<p style="color:red;">Update error. Check your folder permissions.</p>';
		}
	}
	echo '<p>Update the ULeak source files to the latest WordPress version. Find all your hashfiles in the plugin directory (wp-content/plugins/uleak-security-dashboard/hashes/).</p>
		  <form action="'.admin_url("admin-post.php").'" method="post">
		  <input type="hidden" name="action" value="update_sources">
		  <input type="submit" class="button-primary" value="Update sources now" />
		  </form><br /><br />';
	echo '<h3>API Credentials</h3>';
	if(isset($_GET['msg'])){
		if($_GET['msg'] == 0){
			echo '<p style="color:green;">Credentials successful tested.</p>';
		}elseif($_GET['msg'] == 1){
			echo '<p style="color:red;">Plugin connection error.</p>';
		}
	}
	echo '<form action="'.admin_url("admin-post.php").'" method="post">
		  <input type="hidden" name="action" value="add_apikey">';
	if($data->status != 'OK'){
		echo '<table class="form-table">
			<tr>
				<th scope="row"><label>ULeak Username*: </label></th>
				<td><input type="text" name="ul_username" placeholder="Username" value="'.$user['username'].'"><span class="description">(Insert ULeak Username)</span></td>
			</tr>
			<tr>
				<th scope="row"><label>ULeak Password*: </label></th>
				<td><input type="password" name="ul_passwort" placeholder="Password""><span class="description">(Insert ULeak Password. This Password will <b>not</b> be saved in your WP-Database!)</span></td>
			</tr>
			<tr>
				<th scope="row"><label>Email: </label></th>
				<td><input type="text" name="ul_email" placeholder="your@mail.com" value="'.$user['email'].'"><span class="description">(Insert your Email Address for system notifications.)</span></td>
			</tr>
			<tr>
				<th scope="row"><label>ULeak API Key*: </label></th>
				<td><input type="text" name="ul_apikey" placeholder="XXXXXXXXXXX" value="'.$user['apikey'].'"><span class="description">(Insert your ULeak API Key. Find your Credentials <a target="_blank" href="http://uleak.de/login">here</a>)</span></td>
			</tr>';
	}
	echo	'<tr>
				<th scope="row"><label>Connection Status: </label></th>
				<td>';
	if($data->status == 'OK'){ echo '<b style="color:green;">Connected</b>'; }else{ echo '<b style="color:red;">No access</b>'; }
	echo '</td></tr></table>';
	if($data->status != 'OK'){
		echo '<p><i>*Required fields</i></p>';
	}else{
		echo '<br /><br />';
	}
	if($data->status == 'OK'){
		echo '<input type="submit" class="button-primary" value="Reset API Credentials">';
	}else{
		echo '<input type="submit" class="button-primary" value="Save API Credentials">';
	}
	echo '</form><br />';
	if($data->status == 'OK'){
		uleak_results_page();
	}
	echo '</div>';
}
add_action( 'admin_post_update_sources', 'uleak_admin_update_sources' );
function uleak_admin_update_sources() {
	global $wp_version;
	$latest = 'http://wordpress.org/latest.zip';
	$file = 'latest.zip';
	if ( ! is_readable( $file ) ) {
		if ( ! copy( $latest, dirname(__FILE__) . '/hashes/' . $file ) ) {
			$file_error = "No WordPress archive available and it could not be downloaded. Ensure the file is called 'latest.zip'.";
		} else {
			$download = true;
			chdir( dirname(__FILE__) . '/hashes/' );
		}
	}
	$hashes = '<?php' . "\r\n" . '$filehashes = array(' . "\r\n";
	$zip = zip_open( getcwd() . '/' . $file );
	if ( is_resource( $zip ) ) {
		while ( $zip_entry = zip_read( $zip ) ) {
			zip_entry_open( $zip, $zip_entry, 'r' );
			$wp_file = zip_entry_read( $zip_entry, zip_entry_filesize( $zip_entry ) );
			if ( substr( zip_entry_name( $zip_entry ), -1, 1 ) !== '/' && false === strstr( zip_entry_name( $zip_entry ), 'wp-content/plugins/' ) && false === strstr( zip_entry_name( $zip_entry ), 'wp-content/themes/' ) ) {
				list( $wp, $filename ) = explode( '/', zip_entry_name( $zip_entry ), 2 );
				$hashes .= "'" .  $filename . "' => '" . md5( $wp_file ) . "',\r\n";
			}
			zip_entry_close( $zip_entry );
		}
		zip_close( $zip );
	}
	$hashes .= ");\r\n?>";
	if ( isset( $download ) && is_readable( getcwd() . '/' . $file ) ) {
		unlink( dirname(__FILE__) . '/hashes/' . $file );
	}

	if(file_put_contents(dirname(__FILE__) . '/hashes/hashes-'.$wp_version.'.php', $hashes)){
		wp_redirect(admin_url("tools.php?page=uleak&msg=2"));
	}else{
		wp_redirect(admin_url("tools.php?page=uleak&msg=3"));
	}
}
add_action( 'admin_post_add_apikey', 'uleak_admin_add_apikey' );
function uleak_admin_add_apikey() {
	global $wpdb;
	if(!empty($_POST['ul_username'])){
		$result = $wpdb->replace(
			$wpdb->prefix."uleak_customer",
			array(
				'id' => 1,
				'username' => trim($_POST['ul_username']),
				'pwd' => base64_encode($_POST['ul_passwort']),
				'apikey' => $_POST['ul_apikey'],
				'email'=> $_POST['ul_email']
			)
		);
		if($result){
			$login['username'] = trim($_POST['ul_username']);
			$login['passwort'] = $_POST['ul_passwort'];
			$login['apikey'] = $_POST['ul_apikey'];
			$response = curl_helper_post($login, false, 'authenticate_api_user');
			wp_redirect(admin_url("tools.php?page=uleak&msg=0"));
		}else{
			wp_redirect(admin_url("tools.php?page=uleak&msg=1"));
		}
	}else{
		if($wpdb->replace($wpdb->prefix."uleak_customer", array('id' => 1, 'username' => '', 'pwd' => '', 'apikey' => '', 'email'=> ''))){
			$login['username'] = '';
			$login['passwort'] = '';
			$login['apikey'] = '';
			wp_redirect(admin_url("tools.php?page=uleak&msg=0"));
		}else{
			wp_redirect(admin_url("tools.php?page=uleak&msg=1"));
		}
	}
}

/**
 * Display scan initiation form and any stored results.
 */
function uleak_results_page() {
	global $wp_version;
	delete_transient( 'uleak_results_trans' );
	delete_transient( 'uleak_files' );
	$results = get_option( 'uleak_results' );
	?>
	<hr />
	<h3>ULeak Password Alerts</h3>
	<p>ULeak provides a password validation service. This feature will check admin accounts passwords against our Leaked password repository. Our database is created on a regular basis and consists only of already cracked passwords that have been derived from public password-leaks and years of experience from working with hashcat. Furthermore we actively scan for new password leaks to include those to our collection. <br />Current listed passwords: <b>194459270</b></p>
	<?php echo uleak_list_logger(); ?>
	<hr />
	<h3>Complete System Scan</h3>
	<form action="<?php admin_url( 'tools.php?page=uleak' ); ?>" method="post">
		<?php wp_nonce_field( 'uleak-scan_all' ); ?>
		<input type="hidden" name="action" value="scan" />
		<table class="form-table">
			<tr>
				<th scope="row"><label for="filesize_limit">Upper file size limit:</label></th>
				<td><input type="text" size="3" id="filesize_limit" name="filesize_limit" value="400" />KB <span class="description">(files larger than this are skipped and will be listed at the end of scan)</span></td>
			</tr>
			<tr class="hide-if-no-js">
				<th scope="row"><label for="max_test_files">Number of files per batch:</label></th>
				<td>
					<select id="max_test_files" name="max_test_files">
						<option value="100">100</option>
						<option value="150">150</option>
						<option value="250" selected="selected">250</option>
						<option value="500">500</option>
						<option value="1000">1000</option>
					</select>
					<span class="description">(to help reduce memory limit errors the scan processes a series of file batches)</span>
				</td>
			</tr>
		</table>
		<p class="submit"><input type="submit" id="run-scanner" class="button-primary" value="Start Security Scan" /></p>
	</form>
	<div id="scan-loader" style="display:none;margin:10px;padding:10px;background:#f7f7f7;border:1px solid #c6c6c6;text-align:center">
		<p><strong>Searching your filesystem and database for possible exploit code</strong></p>
		<p><span style="margin-right:5px">Files scanned: 0...</span><img src="<?php echo plugins_url( 'img/loader.gif', __FILE__ ); ?>" height="16px" width="16px" alt="loading-icon" /></p>
	</div>
	<div id="scan-results">
		<?php if ( ! $results ) : ?>
			<h3>Results</h3><p>Nothing found.</p>
		<?php else : uleak_show_results( $results ); endif; ?>
	</div>
	<?php
}

/**
 * Display table of results.
 */
function uleak_show_results( $results ) {
	if ( ! is_array($results) ) {
		echo 'Unfortunately the results appear to be malformed/corrupted. Try scanning again.';
		return;
	}
	$result = '<h3>Results</h3><p>Level severe results are synchronized to your ULeak dashboard. To understand the three different result levels click the <button class="button">Help</button> on the top.</p>';
	foreach ( array('severe','warning','note') as $l ) {
		if ( ! empty($results[$l]) ) {
			if ( $l == 'note' ) $result .= '<div style="float:right;font-size:11px;margin-top:1.3em"><a href="#" id="hide-skipped" class="hide-if-no-js">Hide skipped files</a></div>';
			$result .= '<h4>Level ' . ucwords($l) . ' (' . count($results[$l]) . ' matches)</h4>';
			$result .= '<table class="widefat fixed">
			<thead>
			<tr>
				<th scope="col" style="width:50%">Location / Description</th>
				<th scope="col">What was matched</th>
			</tr>
			</thead>
			<tbody>';

			foreach ( $results[$l] as $r )
				$result .= uleak_draw_row( $r );

			$result .= '</tbody></table>';
		}
	}
	echo $result;
}

/**
 * Draw a single result row.
 */
function uleak_draw_row( $r ) {
	$class = ( ! empty($r['class']) ) ? ' class="'.$r['class'].'"' : '';

	$html = '<tr' . $class . '><td><strong>' . esc_html( $r['loc'] );

	if ( ! empty($r['line_no']) )
		$html .= ':' . $r['line_no'] . '</strong>';
	elseif ( ! empty($r['post_id']) )
		$html .= '</strong> <a href="' . get_edit_post_link($r['post_id']) . '" title="Edit this item">Edit</a>';
	elseif ( ! empty($r['comment_id']) )
		$html .= '</strong> <a href="' . admin_url( "comment.php?action=editcomment&amp;c={$r['comment_id']}" ) . '" title="Edit this comment">Edit</a>';
	else
		$html .= '</strong>';

	$html .= '<br />'.$r['desc'].'</td><td>';

	if ( ! empty($r['line']) ) {
		$html .= '<code>' . uleak_hilight( esc_html($r['line']) ) . '</code>';
	} else if ( 'Modified core file' == $r['desc'] ) {
		$url = add_query_arg( array( 'view' => 'diff', 'file' => $r['loc'] ), menu_page_url( 'uleak', false ) );
		$url = wp_nonce_url( $url, 'uleak_view_diff' );
		$html .= '<a href="'.$url.'" id="'.esc_attr($r['loc']).'" class="view-diff">See what has been modified</a>';
	} else if ( ! empty( $r['vuln'] ) ) {
		$url = add_query_arg( array( 'action' => 'fix', 'vulnerability' => $r['vuln'], 'file' => $r['loc'] ), menu_page_url( 'uleak', false ) );
		$url = wp_nonce_url( $url, 'uleak_fix_' . $r['vuln'] . '_' . $r['loc'] );
		$html .= '<a href="'. esc_url( $url ) .'">Fix now</a>';
	}

	return $html . '</td></tr>';
}

/**
 * Display the modifications made to a core file.
 */
function uleak_diff_page() {
	if ( ! current_user_can( 'manage_options' ) )
		die('-1');

	check_ajax_referer( 'uleak_view_diff' );

	$file = $_GET['file'];
	echo '<h3>Changes made to ' . esc_html($file) . '</h3>';
	echo uleak_display_file_diff( $file );

	// exit if this was AJAX
	if ( isset($_GET['_ajax_nonce']) )
		exit;
	// otherwise display return link
	else
		echo '<p><a href="' . menu_page_url('uleak',false) . '">Go back.</a></p>';
}
add_action( 'wp_ajax_uleak_view_diff', 'uleak_diff_page' );

/**
 * Generate the diff of a modified core file.
 */
function uleak_display_file_diff( $file ) {
	global $wp_version;

	// core file names have a limited character set
	$file = preg_replace( '#[^a-zA-Z0-9/_.-]#', '', $file );
	if ( empty( $file ) || ! is_file( ABSPATH . $file ) )
		return '<p>Sorry, an error occured. This file might not exist!</p>';

	$key = $wp_version . '-' . $file;
	$cache = get_option( 'uleak_diff_cache' );
	if ( ! $cache || ! is_array($cache) || ! isset($cache[$key]) ) {
		$url = "http://core.svn.wordpress.org/tags/$wp_version/$file";
		$response = wp_remote_get( $url );
		if ( is_wp_error( $response ) || 200 != $response['response']['code'] )
			return '<p>Sorry, an error occured. Please try again later.</p>';

		$clean = $response['body'];

		if ( is_array($cache) ) {
			if ( count($cache) > 4 ) array_shift( $cache );
			$cache[$key] = $clean;
		} else {
			$cache = array( $key => $clean );
		}
		update_option( 'uleak_diff_cache', $cache );
	} else {
		$clean = $cache[$key];
	}

	$modified = file_get_contents( ABSPATH . $file );

	$text_diff = new Text_Diff( explode( "\n", $clean ), explode( "\n", $modified ) );
	$renderer = new ES_Text_Diff_Renderer();
	$diff = $renderer->render( $text_diff );

	$r  = "<table class='diff'>\n<col style='width:5px' /><col />\n";
	$r .= "<tbody>\n$diff\n</tbody>\n";
	$r .= "</table>";
	return $r;
}

function uleak_fix_vulnerability_page() {
	if ( ! current_user_can( 'edit_plugins' ) )
		wp_die( 'You do not have sufficient permissions to perform this action.' );

	if ( ! in_array( $_GET['vulnerability'], array( 'timthumb' ) ) )
		wp_die( 'Unknown action.' );

	if ( validate_file( $_GET['file'] ) || ! is_file( ABSPATH . $_GET['file'] ) )
		wp_die( 'Invalid file.' );

	if ( ! File_Uleak_Scanner::is_vulnerable_file( $_GET['file'], ABSPATH ) )
		wp_die( 'Invalid file.' );

	check_admin_referer( 'uleak_fix_' . $_GET['vulnerability'] . '_' . $_GET['file'] );

	if ( $_GET['vulnerability'] == 'timthumb' ) {
		echo '<h3>Fixing TimThumb vulnerability</h3>';
		$contents = file_get_contents( ABSPATH . $_GET['file'] );
		$fix = '
		// ULeak security fix
		if ( ! defined( "ALLOW_EXTERNAL" ) || ! ALLOW_EXTERNAL ) {
			$isAllowedSite = false;
			foreach ( $allowedSites as $site ) {
				if ( preg_match (\'/(?:^|\.)\' . preg_quote( $site ) . \'$/i\', $url_info[\'host\'] ) )
					$isAllowedSite = true;
			}
		}
		// End fix
		if ($isAllowedSite) {
		';
		$contents = str_replace( 'if ($isAllowedSite) {', $fix, $contents );
		if ( file_put_contents( ABSPATH . $_GET['file'], $contents ) ) {
			echo '<p>This instance of TimThumb has had a security fix applied. It is recommended that you download the latest version of TimThumb and completely replace this file.</p>';
		} else {
			echo '<p>An error occurred. It was not possible to apply a fix to this file. It is recommended that you download the latest version of TimThumb and completely replace this file.</p>';
		}
	}

	echo '<p>The vulnerability will still show in your scan results until you run another scan.</p>';
	echo '<p><a href="' . menu_page_url('uleak',false) . '">Go back.</a></p>';
}

/**
 * AJAX callback to initiate a file scan.
 */
function uleak_ajax_file_scan() {
	check_ajax_referer( 'uleak_scan' );

	if ( ! isset($_POST['start']) )
		die( json_encode( array( 'status' => 'error', 'data' => 'Error: start not set.' ) ) );
	else
		$start = (int) $_POST['start'];

	$fsl = ( ! isset($_POST['filesize_limit']) || ! is_numeric($_POST['filesize_limit']) ) ? 400 : (int) $_POST['filesize_limit'];
	$max = ( ! isset($_POST['max_batch_size']) || ! is_numeric($_POST['max_batch_size']) ) ? 100 : (int) $_POST['max_batch_size'];

	$args = compact( 'start', 'fsl', 'max' );

	$scanner = new File_Uleak_Scanner( ABSPATH, $args );
	$result = $scanner->run();
	if ( is_wp_error($result) ) {
		$message = $result->get_error_message();
		$data = $result->get_error_data();
		echo json_encode( array( 'status' => 'error', 'message' => $message, 'data' => $data ) );
	} else if ( $result ) {
		echo json_encode( array( 'status' => 'complete' ) );
	} else {
		echo json_encode( array( 'status' => 'running', 'data' => 'Files scanned: ' . ($start+$max) . '...' ) );
	}

	exit;
}
add_action( 'wp_ajax_uleak_file_scan', 'uleak_ajax_file_scan' );

/**
 * AJAX callback to initiate a database scan.
 */
function uleak_ajax_db_scan() {
	check_ajax_referer( 'uleak_scan' );

	$scanner = new DB_Uleak_Scanner();
	$scanner->run();

	echo 'Done';
	exit;
}
add_action( 'wp_ajax_uleak_db_scan', 'uleak_ajax_db_scan' );

function uleak_list_logger() {
	global $wpdb;

	if ( method_exists( $wpdb, 'get_blog_prefix' ) )
		$level_key = $wpdb->get_blog_prefix() . 'capabilities';
	else
		$level_key = $wpdb->prefix . 'capabilities';

	$user_ids = $wpdb->get_col( $wpdb->prepare("SELECT user_id FROM {$wpdb->usermeta} WHERE meta_key = %s AND meta_value LIKE %s", $level_key, '%administrator%') );
	$index = 0;
	foreach ( $user_ids as $id ) {
		$result[$index] = $wpdb->get_results($wpdb->prepare("SELECT * FROM ".$wpdb->prefix.'uleak_users'." WHERE user_id = ".$id." ORDER BY valid_timestamp DESC LIMIT 1"));
		$index++;
	}
	ob_start();
	?>
	<table class="widefat">
		<thead>
		<tr>
			<th scope="col">Username</th>
			<th scope="col">Email</th>
			<th scope="col">Status</th>
			<th scope="col">Last Login</th>
		</tr>
		</thead>
		<tbody>
		<?php
		foreach ( $result as $row ) {
			if(!empty($row)){
				$user = get_userdata(intval($row[0]->user_id));
				echo '<tr><td>'.esc_html($user->user_login).'</td><td>'.esc_html($user->user_email).'</td>';
				if($row[0]->pw_status == 1){echo '<td style="color:red">Password is leaked</td>';}else{echo '<td style="color:red">OK</td>';}
				echo '<td>'.date("d.m.Y, H:i:s", $row[0]->valid_timestamp).'</td></tr>';
			}
		} ?>
		</tbody>
	</table>
	<br />
	<?php
	$admin_table = ob_get_clean();
	return $admin_table;
}

/**
 * Insert highlighted <span> tags around content matched by a scan.
 */
function uleak_hilight( $text ) {
	if ( strlen( $text ) > 200 ) {
		$start = strpos( $text, '$#$#' ) - 50;
		if ( $start < 0 )
			$start = 0;
		$end = strrpos( $text, '#$#$' ) + 50;
		$text = substr( $text, $start, $end - $start + 1 );
	}

	return str_replace( array('$#$#','#$#$'), array('<span style="background:#ff0">','</span>'), $text );
}

/**
 * Activation callback.
 * Add database version info.
 */
function uleak_activate() {
	global $wpdb;
	$db_customer = $wpdb->prefix . "uleak_customer";
	$db_logger = $wpdb->prefix . "uleak_logger";
	$db_users = $wpdb->prefix . "uleak_users";
	if($wpdb->get_var("show tables like '$db_customer'") != $db_customer)
	{
		$sql = "CREATE TABLE " . $db_customer . " (
		`id` mediumint(9) NOT NULL AUTO_INCREMENT,
		`username` varchar(44) NOT NULL,
		`pwd` varchar(88) NOT NULL,
		`apikey` varchar(88) NOT NULL,
		`email` varchar(88) NOT NULL,
		`portfolio_id` mediumint(22) NOT NULL,
		UNIQUE KEY id (id)
		);CREATE TABLE " . $db_logger . " (
		`id` mediumint(9) NOT NULL AUTO_INCREMENT,
		`user_id` mediumint(9) NOT NULL,
		`ip` varchar(44) NOT NULL,
		`login_timestamp` varchar(44) NOT NULL,
		UNIQUE KEY id (id)
		);CREATE TABLE " . $db_users . " (
		`id` mediumint(9) NOT NULL AUTO_INCREMENT,
		`user_id` mediumint(9) NOT NULL,
		`pw_status` mediumint(9) NOT NULL,
		`valid_timestamp` varchar(44) NOT NULL,
		UNIQUE KEY id (id)
		);";
		require_once(ABSPATH . 'wp-admin/includes/upgrade.php');
		dbDelta($sql);
		$wpdb->insert(
			$db_customer,
			array(
				'username' => '',
				'pwd' => '',
				'apikey' => '',
				'email' => '',
				'portfolio_id' => 0
			),
			array(
				'%s',
				'%s',
				'%s',
				'%d'
			)
		);
	}
	//Use wp_next_scheduled to check if the event is already scheduled
	$timestamp = wp_next_scheduled( 'uleak_create_daily_backup' );
	if( $timestamp == false ){
		//Schedule the event for right now, then to repeat daily using the hook 'uleak_create_daily_backup'
		wp_schedule_event( time(), 'twicedaily', 'uleak_create_daily_backup' );
	}

	add_option( 'uleak', 1 );
	add_option( 'uleak_results', 0, '', 'no' );
	add_option( 'uleak_diff_cache', 0, '', 'no' );
	register_uninstall_hook( __FILE__, 'uleak_uninstall' );
}
register_activation_hook( __FILE__, 'uleak_activate' );

add_action( 'uleak_create_daily_backup', 'uleak_create_backup' );
function uleak_create_backup(){
	global $wpdb;
	$scanner = new File_Uleak_Scanner( ABSPATH, array( 'start' => 0, 'fsl' => 600 ) );
	$scanner->run();
	$scanner = new DB_Uleak_Scanner();
	$scanner->run();
	delete_transient( 'uleak_results_trans' );
	delete_transient( 'uleak_files' );
	$results = get_option('uleak_results');
	$user_credentials = $wpdb->get_results( 'SELECT * FROM '.$wpdb->prefix ."uleak_customer".' WHERE id = 1 LIMIT 1');
	foreach($user_credentials as $key => $row) {
		$login['username'] = $row->username;
		$login['passwort'] = base64_decode($row->pwd);
		$login['apikey'] = $row->apikey;
		$portfolio_id = $row->portfolio_id;
	}
	$response = curl_helper_post($login, $results['severe'], 'malware_result_transfer', $portfolio_id);
	if($response->status == 'OK'){
		// transfer to uleak dashboard done
	}

}

/**
 * Deactivation callback. Remove transients.
 */
function uleak_deactivate() {
	global $wpdb;
	$table_name[0] = $wpdb->prefix."uleak_customer";
	$table_name[1] = $wpdb->prefix."uleak_logger";
	$table_name[2] = $wpdb->prefix."uleak_users";
	for ($i=0; $i < count($table_name); $i++) {
		$sql = "DROP TABLE ".$table_name[$i];
		$wpdb->query($sql);
	}
	wp_clear_scheduled_hook( 'uleak_create_daily_backup' );
	delete_transient( 'uleak_results_trans' );
	delete_transient( 'uleak_files' );
}
register_deactivation_hook( __FILE__, 'uleak_deactivate' );

/**
 * Uninstall callback. Remove all data stored by the plugin.
 */
function uleak_uninstall() {
	delete_option( 'uleak' );
	delete_option( 'uleak_results' );
	delete_option( 'uleak_diff_cache' );
}

/**
 * Update routine to perform database cleanup and to ensure that newly
 * introduced settings and defaults are enforced.
 */
function uleak_update() {
	$db_version = 1;
	$local_version = get_option( 'uleak' );
	if ( false === $local_version || $local_version < $db_version ) {
		$count = get_option( 'uleak_result_count' );
		if ( $count ) {
			$opts = array('uleak_result_count','uleak_file_count','uleak_other','uleak_wp-admin','uleak_wp-content','uleak_wp-includes');
			foreach ( $opts as $opt )
				delete_option( $opt );

			for( $i = 0; $i < $count; $i++ )
				delete_option( 'uleak_results_' . $i );
		}
		delete_option( 'uleak_results' );
		uleak_activate();
	}
}
add_action( 'admin_init', 'uleak_update' );

/**
 * ULeak base class. Scanners should extend this.
 */
class Uleak_Scanner {
	var $results;

	function __construct() {}

	function add_result( $level, $info ) {
		$this->results[$level][] = $info;
	}

	function store_results( $done = false ) {
		$stored = get_transient( 'uleak_results_trans' );
		if ( empty($this->results) ) {
			if ( $done )
				update_option( 'uleak_results', $stored );
			return;
		}

		if ( $stored && is_array($stored) )
			$this->results = array_merge_recursive( $stored, $this->results );

		if ( $done ) {
			update_option( 'uleak_results', $this->results );
			delete_transient( 'uleak_results_trans' );
		} else {
			set_transient( 'uleak_results_trans', $this->results );
		}
	}
}

/**
 * File Scanner. Scans all files in given path for suspicious text.
 */
class File_Uleak_Scanner extends Uleak_Scanner {
	var $path;
	var $start;
	var $filesize_limit;
	var $max_batch_size;
	var $paged = true;
	var $files = array();
	var $modified_files = array();
	var $skip;
	var $complete = false;
	var $suspicious_patterns = array(
		'/(\$wpdb->|mysql_).+DROP/siU' => array( 'level' => 'note', 'desc' => 'Possible database table deletion' ),
		'/(echo|print|<\?=).+(\$GLOBALS|\$_SERVER|\$_GET|\$_REQUEST|\$_POST)/siU' => array( 'level' => 'note', 'desc' => 'Possible output of restricted variables' ),
		'/ShellBOT/i' => array( 'level' => 'severe', 'desc' => 'This may be a script used by hackers to get control of your server' ),
		'/uname -a/i' => array( 'level' => 'severe', 'desc' => 'Tells a hacker what operating system your server is running' ),
		'/YW55cmVzdWx0cy5uZXQ=/i' => array( 'level' => 'severe', 'desc' => 'base64 encoded text found in Search Engine Redirect hack' ),
		'/[^\w]eval\s*\(/i' => array( 'level' => 'severe', 'desc' => 'Often used to execute malicious code' ),
		'/\$_COOKIE\[\'yahg\'\]/i' => array( 'level' => 'severe', 'desc' => 'YAHG Googlerank.info exploit code' ),
		'/ekibastos/i' => array( 'level' => 'severe', 'desc' => 'Possible Ekibastos attack'),
		'/base64_decode\s*\(/i' => array( 'level' => 'severe', 'desc' => 'Used by malicious scripts to decode previously obscured data/programs' ),
		'/<script>\/\*(GNU GPL|LGPL)\*\/ try\{window.onload.+catch\(e\) \{\}<\/script>/siU' => array( 'level' => 'severe', 'desc' => 'Possible "Gumblar" JavaScript attack' ),
		'/php \$[a-zA-Z]*=\'as\';/i' => array( 'level' => 'severe', 'desc' => 'Symptom of the "Pharma Hack"' ),
		'/defined?\(\'wp_class_support/i' => array( 'level' => 'severe', 'desc' => 'Symptom of the "Pharma Hack"' ),
		'/str_rot13/i' => array( 'level' => 'severe', 'desc' => 'Decodes/encodes text using ROT13. Could be used to hide malicious code.' ),
		'/uudecode/i' => array( 'level' => 'severe', 'desc' => 'Decodes text using uuencoding. Could be used to hide malicious code.' ),
		//'/[^_]unescape/i' => array( 'level' => 'severe', 'desc' => 'JavaScript function to decode encoded text. Could be used to hide malicious code.' ),
		'/<!--[A-Za-z0-9]+--><\?php/i' => array( 'level' => 'warning', 'desc' => 'Symptom of a link injection attack' ),
		'/<iframe/i' => array( 'level' => 'warning', 'desc' => 'iframes are sometimes used to load unwanted adverts and code on your site' ),
		'/String\.fromCharCode/i' => array( 'level' => 'warning', 'desc' => 'JavaScript sometimes used to hide suspicious code' ),
		'/preg_replace\s*\(\s*(["\'])(.).*(?<!\\\\)(?>\\\\\\\\)*\\2([a-z]|\\\x[0-9]{2})*(e|\\\x65)([a-z]|\\\x[0-9]{2})*\\1/si' => array( 'level' => 'warning', 'desc' => 'The e modifier in preg_replace can be used to execute malicious code' ),
	);

	function __construct( $path, $args ) {
		$this->path = $path;

		if ( ! empty($args['max']) )
			$this->max_batch_size = $args['max'];
		else
			$this->paged = false;

		$this->start = $args['start'];
		$this->filesize_limit = $args['fsl'];
		$this->skip = ltrim( str_replace( array( untrailingslashit( ABSPATH ), '\\' ), array( '', '/' ), __FILE__ ), '/' );
	}

	function File_Uleak_Scanner( $path, $args ) {
		$this->__construct( $path, $args );
	}

	function run() {
		$this->get_files( $this->start );
		$this->file_pattern_scan();
		$this->store_results();
		return $this->complete;
	}

	function get_files( $s ) {
		global $wp_version;

		if ( 0 == $s ) {
			unset( $filehashes );
			$hashes = dirname(__FILE__) . '/hashes/hashes-'. $wp_version .'.php';
			if ( file_exists( $hashes ) )
				include( $hashes );
			else
				$this->add_result( 'severe', array(
					'loc' => 'hashes-'. $wp_version .'.php missing',
					'desc' => 'The file containing hashes of all WordPress core files appears to be missing; modified core files will no longer be detected and a lot more suspicious strings will be detected'
				) );

			$this->recurse_directory( $this->path );

			foreach( $this->files as $k => $file ) {
				// don't scan unmodified core files
				if ( isset( $filehashes[$file] ) ) {
					if ( $filehashes[$file] == md5_file( $this->path.'/'.$file ) ) {
						unset( $this->files[$k] );
						continue;
					} else {
						$this->add_result( 'warning', array(
							'loc' => $file,
							'desc' => 'Modified core file'
						) );
					}
				} else {
					list( $dir ) = explode( '/', $file );
					if ( $dir == 'wp-includes' || $dir == 'wp-admin' ) {
						$severity = substr( $file, -4 ) == '.php' ? 'severe' : 'warning';
						$this->add_result( $severity, array(
							'loc' => $file,
							'desc' => 'Unknown file found in wp-includes/ or wp-admin/ directory.'
						) );
					}
				}

				// detect old export files
				if ( substr( $file, -9 ) == '.xml_.txt' ) {
					$this->add_result( 'warning', array(
						'loc' => $file,
						'desc' => 'It is likely that this is an old export file. If so it is recommended that you delete this file to stop it from exposing potentially private information.'
					) );
				}

				$vulnerable_file = $this->is_vulnerable_file( $file, $this->path . '/' );
				if ( $vulnerable_file ) {
					$this->add_result( 'severe', array(
						'loc' => $file,
						'desc' => $vulnerable_file['desc'],
						'vuln' => $vulnerable_file['vuln']
					) );
				}

				// don't scan files larger than given limit
				if ( filesize($this->path . $file) > ($this->filesize_limit * 1024) ) {
					unset( $this->files[$k] );
					$this->add_result( 'note', array(
						'loc' => $file,
						'desc' => 'File skipped due to size',
						'class' => 'skipped-file'
					) );
				}
			}

			$this->files = array_values( $this->files );
			$result = set_transient( 'uleak_files', $this->files, 3600 );

			if ( ! $result ) {
				$this->paged = false;
				$data = array( 'files' => esc_html( serialize( $this->files ) ) );
				if ( ! empty($GLOBALS['EZSQL_ERROR']) )
					$data['db_error'] = $GLOBALS['EZSQL_ERROR'];
				$this->complete = new WP_Error( 'failed_transient', '$this->files was not properly saved as a transient', $data );
			}
		} else {
			$this->files = get_transient( 'uleak_files' );
		}

		if ( ! is_array( $this->files ) ) {
			$data = array(
				'start' => $s,
				'files' => esc_html( serialize( $this->files ) ),
			);

			if ( ! empty( $GLOBALS['EZSQL_ERROR'] ) )
				$data['db_error'] = $GLOBALS['EZSQL_ERROR'];

			$this->complete = new WP_Error( 'no_files_array', '$this->files was not an array', $data );
			$this->files = array();
			return;
		}

		// use files list to get a batch if paged
		if ( $this->paged && (count($this->files) - $s) > $this->max_batch_size ) {
			$this->files = array_slice( $this->files, $s, $this->max_batch_size );
		} else {
			$this->files = array_slice( $this->files, $s );
			if ( ! is_wp_error( $this->complete ) )
				$this->complete = true;
		}
	}

	function recurse_directory( $dir ) {
		if ( $handle = @opendir( $dir ) ) {
			while ( false !== ( $file = readdir( $handle ) ) ) {
				if ( $file != '.' && $file != '..' ) {
					$file = $dir . '/' . $file;
					if ( is_dir( $file ) ) {
						$this->recurse_directory( $file );
					} elseif ( is_file( $file ) ) {
						$this->files[] = str_replace( $this->path.'/', '', $file );
					}
				}
			}
			closedir( $handle );
		}
	}

	function file_pattern_scan() {
		foreach ( $this->files as $file ) {
			if ( $file != $this->skip ) {
				$contents = file( $this->path . $file );
				foreach ( $contents as $n => $line ) {
					foreach ( $this->suspicious_patterns as $pattern => $p ) {
						$test = preg_replace_callback( $pattern, array( &$this, 'replace' ), $line );
						if ( $line !== $test ) {
							$test = trim( $test );

							$start = strpos( $test, '$#$#' ) - 50;
							if ( $start < 0 )
								$start = 0;

							$append = '';
							$end = strrpos( $test, '#$#$' );
							// if the text to display is longer than 150 characters truncate it
							if ( ( $end - $start ) > 150 ) {
								$end = $start + 150;
								$append = '#$#$ [line truncated]';
							} else {
								$end += 50;
							}

							$test = substr( $test, $start, $end - $start + 1 ) . $append;

							$this->add_result( $p['level'], array(
								'loc' => $file,
								'line' => esc_html( $test ),
								'line_no' => $n+1,
								'desc' => $p['desc']
							) );
						}
					}
				}
			}
		}
	}

	function replace( $matches ) {
		return '$#$#' . $matches[0] . '#$#$';
	}

	function is_vulnerable_file( $file, $path ) {
		$timthumb = array( 'timthumb.php', 'thumb.php', 'thumbs.php', 'thumbnail.php', 'thumbnails.php', 'thumnails.php', 'cropper.php', 'picsize.php', 'resizer.php' );
		if ( in_array( strtolower( basename( $file ) ), $timthumb ) ) {
			$contents = file_get_contents( $path . $file );
			if (
				false !== strpos( $contents, 'TimThumb' ) &&
				false !== strpos( $contents, '$allowedSites' ) &&
				false === strpos( $contents, 'ULeak security fix' ) &&
				false === strpos( $contents, 'VaultPress HotFix' )
			) {
				$version = 'unknown';
				if ( preg_match( "/define\s*\([\\'\"]VERSION[\\'\"]\s*,\s*[\\'\"](.*)[\\'\"]/", $contents, $matches ) )
					$version = $matches[1];

				if ( 'unknown' == $version || version_compare( $version, '1.34', '<' ) )
					return array(
						'desc' => sprintf( 'You are using an old version (%s) of TimThumb. This could allow attackers to take control of your site.', esc_html( $version ) ),
						'vuln' => 'timthumb'
					);
			}
		}

		return false;
	}
}

/**
 * Database Scanner. Scans WordPress database for suspicious post/comment text and plugins.
 */
class DB_Uleak_Scanner extends Uleak_Scanner {
	var $suspicious_text = array(
		'eval(' => array( 'level' => 'severe', 'desc' => 'Often used by hackers to execute malicious code' ),
		'<script' => array( 'level' => 'severe', 'desc' => 'JavaScript hidden in the database is normally a sign of a hack' ),
	);

	var $suspicious_post_text = array(
		'<iframe' => array( 'level' => 'warning', 'desc' => 'iframes are sometimes used to load unwanted adverts and code on your site' ),
		'<noscript' => array( 'level' => 'warning', 'desc' => 'Could be used to hide spam in posts/comments' ),
		'display:' => array( 'level' => 'warning', 'desc' => 'Could be used to hide spam in posts/comments' ),
		'visibility:' => array( 'level' => 'warning', 'desc' => 'Could be used to hide spam in posts/comments' ),
		'<script' => array( 'level' => 'severe', 'desc' => 'Malicious scripts loaded in posts by hackers perform redirects, inject spam, etc.' ),
	);
	function __construct() {}
	function DB_Uleak_Scanner() {
		$this->__construct();
	}
	function run() {
		$this->scan_posts();
		$this->scan_plugins();
		$this->store_results(true);
	}
	function replace( $content, $text ) {
		$s = strpos( $content, $text ) - 25;
		if ( $s < 0 ) $s = 0;

		$content = preg_replace( '/('.$text.')/', '$#$#\1#$#$', $content );
		$content = substr( $content, $s, 150 );
		return $content;
	}
	function scan_posts() {
		global $wpdb;

		foreach ( $this->suspicious_post_text as $text => $info ) {
			$posts = $wpdb->get_results( "SELECT ID, post_title, post_content FROM {$wpdb->posts} WHERE post_type<>'revision' AND post_content LIKE '%{$text}%'" );
			if ( $posts )
				foreach ( $posts as $post ) {
					$content = $this->replace( $post->post_content, $text );

					$this->add_result( $info['level'], array(
						'loc' => 'Post: ' . esc_html($post->post_title),
						'line' => esc_html($content),
						'post_id' => $post->ID,
						'desc' => $info['desc']
					) );
				}

			$comments = $wpdb->get_results( "SELECT comment_ID, comment_author, comment_content FROM {$wpdb->comments} WHERE comment_content LIKE '%{$text}%'" );
			if ( $comments )
				foreach ( $comments as $comment ) {
					$content = $this->replace( $comment->comment_content, $text );

					$this->add_result( $info['level'], array(
						'loc' => 'Comment by ' . esc_html($comment->comment_author),
						'line' => esc_html($content),
						'comment_id' => $comment->comment_ID,
						'desc' => $info['desc']
					) );
				}
		}
	}

	function scan_plugins() {
		$active_plugins = get_option( 'active_plugins' );
		if ( ! empty( $active_plugins ) && is_array( $active_plugins ) ) {
			foreach ( $active_plugins as $plugin ) {
				if ( strpos( $plugin, '..' ) !== false || substr( $plugin, -4 ) != '.php' ) {
					if ( $plugin == '' )
						$desc = 'Blank entry found. Should be removed. It will look like \'i:0;s:0:\"\";\' in the active_records field.';
					else
						$desc = 'Active plugin with a suspicious name.';

					$this->add_result( 'severe', array(
						'loc' => 'Plugin: ' . esc_html( $plugin ),
						'desc' => $desc
					) );
				}
			}
		}
	}
}

include_once( ABSPATH . WPINC . '/wp-diff.php' );

if ( class_exists( 'Text_Diff_Renderer' ) ) :
	class ES_Text_Diff_Renderer extends Text_Diff_Renderer {
		function ES_Text_Diff_Renderer() {
			parent::Text_Diff_Renderer();
		}
		function _startBlock( $header ) {
			return "<tr><td></td><td><code>$header</code></td></tr>\n";
		}
		function _es_lines( $lines, $prefix, $class ) {
			$r = '';
			foreach ( $lines as $line ) {
				$line = esc_html( $line );
				$r .= "<tr><td>{$prefix}</td><td class='{$class}'>{$line}</td></tr>\n";
			}
			return $r;
		}
		function _added( $lines ) {
			return $this->_es_lines( $lines, '+', 'diff-addedline' );
		}
		function _deleted( $lines ) {
			return $this->_es_lines( $lines, '-', 'diff-deletedline' );
		}
		function _context( $lines ) {
			return $this->_es_lines( $lines, '', 'diff-context' );
		}
		function _changed( $orig, $final ) {
			return $this->_deleted( $orig ) . $this->_added( $final );
		}
	}
endif;

function uleak_plugin_actions( $links, $file ) {
	if( $file == 'uleak/uleak.php' && function_exists( "admin_url" ) ) {
		$settings_link = '<a href="' . admin_url( 'tools.php?page=uleak' ) . '">' . __('Settings') . '</a>';
		array_unshift( $links, $settings_link ); // before other links
	}
	return $links;
}
add_filter( 'plugin_action_links', 'uleak_plugin_actions', 10, 2 );

function uleak_auth_login($user, $password) {
	global $wpdb;
	if(wp_check_password($password, $user->data->user_pass, $user->ID)){
		foreach($wpdb->get_results( 'SELECT * FROM '.$wpdb->prefix."uleak_customer".' LIMIT 1') as $key => $row) {
			wp_schedule_single_event( time(), 'validate_user_password', array( $user, $password , $row->apikey, intval($row->portfolio_id)));
		}
	}
	return $user;
}
add_filter('wp_authenticate_user', 'uleak_auth_login',10,2);

function action_wp_login_failed($username) {
	global $wpdb;
	$wpdb->insert(
		$wpdb->prefix."uleak_logger",
		array(
			'user_id' => 0,
			'ip' => GetIP(),
			'login_timestamp' => time()
		),
		array(
			'%d',
			'%s',
			'%s'
		)
	);
};
add_action( 'wp_login_failed', 'action_wp_login_failed', 10, 1 );

function uleak_validate_password($user, $password, $api_key, $portfolio_id){
	global $wpdb;
	if($api_key != '' && $portfolio_id != 0){
		$json = file_get_contents('https://www.uleak.de/cv/checkmd5.pl?checkmd5='.$password.'&apikey='.$api_key.'&pid='.$portfolio_id);
		$result = intval(json_decode($json));
		$wpdb->insert(
			$wpdb->prefix."uleak_users",
			array(
				'user_id' => $user->ID,
				'pw_status' => $result,
				'valid_timestamp' => time()
			),
			array(
				'%d',
				'%d',
				'%s'
			)
		);
		if($result == 1){
			// Email text
			$text = "<html><body><p>Hello ".$user->user_nicename.",<br /> your account password was found in a leaked repository. Improve your security and reset your password <a href='".get_site_url()."/wp-login.php'>here.</a><br />This message was send automatically from your wordpress installation at <a href='".get_site_url()."'>".get_site_url()."</a></p></body></html>";
			// Email headers
			$headers = array(
				'From: WP-ULeak Password Service <'.get_settings('admin_email').'>',
				"Content-Type: text/html"
			);
			$h = implode("\r\n",$headers) . "\r\n";
			// Send email
			wp_mail($user->user_email, 'ULeak Password Alert', $text, $h);
		}
	}
}
add_action('validate_user_password', 'uleak_validate_password', 10, 4);

function GetIP(){
	foreach(array('HTTP_CLIENT_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_FORWARDED', 'HTTP_X_CLUSTER_CLIENT_IP', 'HTTP_FORWARDED_FOR', 'HTTP_FORWARDED', 'REMOTE_ADDR') as $key){
		if (array_key_exists($key, $_SERVER) === true){
			foreach (array_map('trim', explode(',', $_SERVER[$key])) as $ip){
				if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) !== false){
					return $ip;
				}
			}
		}
	}
}

function curl_helper_post($login, $transferData = false, $targetMethod = false, $portfolio_id = false){
	$service_url = 'http://www.uleak.de/api/restful/'.$targetMethod;
	$curl = curl_init($service_url);
	$curl_post_data = array('id' => $login['apikey'], 'data' => json_encode($transferData), 'portfolio_id' => intval($portfolio_id), 'request_url' => site_url());
	curl_setopt($curl, CURLOPT_HTTPAUTH, CURLAUTH_DIGEST);
	curl_setopt($curl, CURLOPT_USERPWD, $login['username'].':'.$login['passwort']);
	curl_setopt($curl, CURLOPT_NOBODY, 1);
	curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
	curl_setopt($curl, CURLOPT_POST, true);
	curl_setopt($curl, CURLOPT_POSTFIELDS, $curl_post_data);
	$curl_response = curl_exec($curl);
	if ($curl_response === false) {
		$info = curl_getinfo($curl);
		curl_close($curl);
		die('error occured during curl exec. Additioanl info: ' . var_export($info));
	}
	curl_close($curl);

	$decoded = json_decode($curl_response);
	if (isset($decoded->response->status) && $decoded->response->status == 'ERROR') {
		die('error occured: ' . $decoded->response->errormessage);
	}
	return $decoded;
}


