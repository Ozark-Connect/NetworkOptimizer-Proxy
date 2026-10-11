# CRS plugins

Copy the `.conf` files from an OWASP CRS plugin's `plugins/` folder here and restart `netopt-waf`.
Rule exclusion plugins for WordPress, Nextcloud, Drupal, phpMyAdmin, and more are listed in the
[CRS plugin registry](https://github.com/coreruleset/plugin-registry).

They load in the CRS plugin order: every `*-config.conf`, then `*-before.conf`, then the Core Rule
Set, then `*-after.conf`. A plugin applies to every host behind the WAF until you scope it in its
`-config.conf`; the main README has an example. Only `.conf` files are read.
