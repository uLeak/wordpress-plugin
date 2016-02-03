<?php
/*
 Hash file generator for ULeak
*/
if(isset($_GET['wp_version'])){
	$latest = 'http://wordpress.org/latest.zip';
	$file = 'latest.zip';
	$wp_version = preg_replace('[^0-9\.]', '',  $_GET['wp_version']);
	if ( ! is_readable( $file ) ) {
		if ( ! copy( $latest, '/tmp/' . $file ) ) {
			$file_error = "No WordPress archive available and it could not be downloaded. Ensure the file is called 'latest.zip'.";
		} else {
			$download = true;
			chdir( '/tmp' );
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
		unlink( '/tmp/' . $file );
	}
	$file = 'hashes-'.$wp_version.'.php';
	$current = file_get_contents($file);
	$current .= $hashes;
	file_put_contents(dirname(__FILE__) . '/hashes-'.$wp_version.'.php', $current);
}