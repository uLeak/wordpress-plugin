=== ULeak Security Monitoring by CrossVault ===

Contributors: zephyrus1337
Company link: http://uleak.de
Tags: ULeak, malware monitoring, password security, cloud security, multi-website monitoring, hacked, availability monitoring, security monitoring
Stable tag: 4.4.2
Requires at least: 3.8
Tested up to: 4.4.2
License: GPLv2 or later
License URI: http://www.gnu.org/licenses/gpl-2.0.html

== Description ==

ULeak is one of the best and most coherent cloud-based security scanner today. We aim to provide website owners the most concise security resource on the web and the best management tool for their projects.
This plugin searches the files on your website, and the posts and comments tables of your database for anything suspicious. It also examines your list of active plugins for unusual filenames.
This plugin is a scanning application that does not remove anything. It`s also just a additional feature of our regular services as website security provider especially for our WordPress users. 
Find more details in our "How does it works" section on http://www.uleak.de.

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
No! To use the core features of the plugin a ULeak membership is required. Get more details about our pricing here (http://uleak.de/pricing). 

= Can I get a Free Trial? =
If you wish to trial the service simply sign up and if you are not happy with the results you can get a money back refund within 5 days of purchase.

= Is the payment for a recurring subscription? =
No you are not locked into any subscription. The Beginner, Pro and Expert membership lasts for 12 months and will expire if you do not chose to renew. A reminder email will be sent 14 days before expiry.

= How does the payment system work? =
Payment is via Credit Card or PayPal. There are No lock in contracts or subscriptions. Once payment is made you will be directed to a signup page where you enter your primary email; this will be used for the login and delivery of your scan results.

= Can I upgrade or change plans? =
Yes, we offer various upgrade options once you are subscribed. If you do not find the upgrade you're looking for, please submit a ticket and our support team will help.

= Are there any additional taxes or fees? =
There are no extra fees, no additional taxes, and no hidden costs. The price you see is the price that you pay. All of our prices are listed in USD, and the conversion will be automatically handled by Paypal.

= Will the WordPress plugin remove malware from my website? =
The ULeak Scanner Plugin for wordpress will audit and detect malware using a remote scanner. It does not remove malware, but does offer a path to the payload when available, and additional recommendations to help you get your website cleaned.

= Do I have to do anything to activate the ULeak plugin? =
It is just required to install and activate the plugin. A automated update will produced optimized on your wordpress version. Our plugin works as paid service an you have to register a membership subscription to activate the plugin by using an API key from your ULeak dashboard.

= Do the WordPress plugins work with Multisite installations? =
Yes! Multisite installations will need to use one installation of the plugin, which means all the sites will share the scanning results and leaked password information to your ULeak cloud.

= How often are new features added? =
We regularly maintain and update our extensions for compatibility and feature enhancements. You can subscribe to receive notifications of updates from the offical wordpress plugin repository (svn) or from github.

= Interpreting the Results =
It is possible that the scanner will find false positives (i.e. files which do not contain malicious code). If you are unsure feel welcome to ask our support (http://uleak.de/support/),
You should be most concerned if the scanner is:
* making matches around unknown external links
* finding base64 encoded text in modified core files or the `wp-config.php` file;
* listing extra admin accounts
* or finding content in posts which you did not put there.


== Screenshots ==

See http://www.uleak.de


== Upgrade Notice ==
Version 1.1

== Changelog ==
= 1.0 =
First Beta Version
= 1.1 =
Added ULeak SECURE Seal
Release date: May 1th, 2016