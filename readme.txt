=== ULeak Security Dashboard by CrossVault ===
Contributors: zephyrus1337
Donate link: http://uleak.de
Tags: WordPress.com, uleak, malware, password, security, performance, backdoor, hacked, availability monitoring
Stable tag: 4.3
Requires at least: 4.3
Tested up to: 4.4
License: GPLv2 or later
License URI: http://www.gnu.org/licenses/gpl-2.0.html

== Description ==
ULeak is one of the best and most coherent cloud-based security scanner today. We aim to provide website owners the most concise security resource on the web and the best management tool for their projects.
This plugin searches the files on your website, and the posts and comments tables of your database for anything suspicious. It also examines your list of active plugins for unusual filenames.
This plugin is a scanning application that does not remove anything.

= Malware scan =
This plugin provides a malware scan to find all backdoor scripts and potential risks on your Wordpress installation. Log in to your ULeak API account to synchronize daily scanning results to your Uleak dashboard. You can find the daily synchronisation process in the Wordpress cron event schedular. We will send you also an email alert if a scanner finds an infected file.

= Leaked password validation =
This feature will check admin accounts passwords against our Leaked password repository. Our database is created on a regular basis and consists only of already cracked passwords that have been derived from public password-leaks and years of experience from working with hashcat. Furthermore we actively scan for new password leaks to include those to our collection.
Current listed passwords: 194459270

= Cloud based result synchronization =
The plugin scheduled a daily result transfer to your ULeak Dashboard.

= Security =
ULeak **protects your site** against malware, backdoor scripts and xss attacks. Also unauthorised logins and leaked admin passwords will be detected. We also monitor your site for downtime.

= Dedicated Support =
We have a team of engineers ready to help you.  Ask your questions at our helpdesk at http://uleak.de/support.


== Installation ==
[Download ULeak from our site](http://uleak.de/home/download/file_01). Alternatively install ULeak via the plugin directory, or by uploading the files manually to your server. After activating the plugin a automatic update will be executed to hit the required Wordpress version.
A new menu item called "ULeak Security" will be available under the Tools menu.
If you need additional help contact our support at http://uleak.de/support.


== Frequently Asked Questions ==

= Is ULeak free? =
No! To use the core features of the plugin a ULeak membership is required. Get more details about our pricing here (http://uleak.de/pricing)

= Interpreting the Results =
It is possible that the scanner will find false positives (i.e. files which do not contain malicious code). If you are unsure feel welcome to ask our support (http://uleak.de/support/),
You should be most concerned if the scanner is:
* making matches around unknown external links
* finding base64 encoded text in modified core files or the `wp-config.php` file;
* listing extra admin accounts
* or finding content in posts which you did not put there.


== Screenshots ==
1. ULeak Plugin.


== Upgrade Notice ==
Version 1.0

== Changelog ==
= 1.0 =
Release date: May 1th, 2016